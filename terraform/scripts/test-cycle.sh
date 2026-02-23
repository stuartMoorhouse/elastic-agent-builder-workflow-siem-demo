#!/bin/bash

################################################################################
# SIEM Demo - Full Test Cycle
#
# Recreates solr-kb VM from scratch, installs Elastic Agent, waits for event
# collection to start, then runs the Log4Shell exploit. This ensures every
# test starts from a clean state with no event collection gaps.
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/test-cycle.sh
################################################################################

set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-common.sh"
trap 'cleanup_curl_auth' EXIT

################################################################################
# Steps 1-5: Shared VM setup (same as reset-solr-red-vm.sh)
################################################################################

print_phase "STEP 1: Reading Terraform outputs"
read_terraform_outputs
read_vm_ips
print_vm_ips

print_phase "STEP 2: Recreating solr-kb VM"
recreate_solr_kb

print_phase "STEP 3: Waiting for cloud-init and Solr"
wait_for_solr_kb

print_phase "STEP 4: Installing Elastic Agent"
install_agent_solr_kb

print_phase "STEP 5: Waiting for process events to appear in Elasticsearch"
wait_for_process_events

################################################################################
# STEP 6: Run the exploit (non-interactive to verify pipeline)
################################################################################

print_phase "STEP 6: Running Log4Shell exploit"

print_info "Exploiting solr-kb ($SOLR_KB_PRIVATE_IP) from attacker ($REDTEAM_PRIVATE_IP)..."

# Run exploit non-interactively with a timeout to verify the shell establishes.
# The interactive session comes in step 8 after alert verification.
TIMEOUT_CMD=""
if command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout 120"
elif command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout 120"
fi

if [ -n "$TIMEOUT_CMD" ]; then
    EXPLOIT_OUTPUT=$($TIMEOUT_CMD ssh $SSH_OPTS "$SSH_USER@$REDTEAM_PUBLIC_IP" \
        "bash /home/ubuntu/scripts/host-scan.sh -t $SOLR_KB_PRIVATE_IP -a $REDTEAM_PRIVATE_IP" 2>&1 || true)
else
    # No timeout command — run in background, wait up to 120s, then kill
    ssh $SSH_OPTS "$SSH_USER@$REDTEAM_PUBLIC_IP" \
        "bash /home/ubuntu/scripts/host-scan.sh -t $SOLR_KB_PRIVATE_IP -a $REDTEAM_PRIVATE_IP" > /tmp/exploit-output.txt 2>&1 &
    EXPLOIT_PID=$!
    for i in $(seq 1 24); do
        if ! kill -0 $EXPLOIT_PID 2>/dev/null; then break; fi
        if [ -f /tmp/exploit-output.txt ] && grep -q "Reverse shell established" /tmp/exploit-output.txt 2>/dev/null; then
            sleep 2  # let it finish writing
            kill $EXPLOIT_PID 2>/dev/null || true
            break
        fi
        sleep 5
    done
    kill $EXPLOIT_PID 2>/dev/null || true
    wait $EXPLOIT_PID 2>/dev/null || true
    EXPLOIT_OUTPUT=$(cat /tmp/exploit-output.txt 2>/dev/null || echo "")
fi

echo "$EXPLOIT_OUTPUT" | tail -20

if echo "$EXPLOIT_OUTPUT" | grep -q "Reverse shell established"; then
    print_info "Exploit succeeded — reverse shell established!"
else
    print_error "Exploit may have failed. Check output above."
    exit 1
fi

################################################################################
# STEP 7: Wait for alert and check workflow
################################################################################

print_phase "STEP 7: Waiting for detection alert"

print_info "Detection rule: 'Shell Spawned by Java Process' (interval: 10s, lookback: 2m)"
print_info "Waiting up to 2 minutes for alert..."

ALERT_FOUND=false
for i in $(seq 1 24); do
    ALERT_COUNT=$(curl -s -K "$CURL_AUTH_CONF" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/detection_engine/signals/search" \
        -d '{
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"kibana.alert.rule.name": "Shell Spawned by Java Process"}},
                        {"range": {"@timestamp": {"gte": "now-5m"}}}
                    ]
                }
            },
            "size": 0
        }' 2>/dev/null | jq -r '.hits.total.value // 0' 2>/dev/null)

    if [ "$ALERT_COUNT" -gt 0 ] 2>/dev/null; then
        print_info "Alert fired! ($ALERT_COUNT alert(s) in last 5 minutes)"
        ALERT_FOUND=true
        break
    fi
    [ $((i % 6)) -eq 0 ] && print_info "  Still waiting... ($((i * 5))s elapsed)"
    sleep 5
done

if [ "$ALERT_FOUND" = false ]; then
    print_warn "No alert detected after 2 minutes."
    print_warn "Check manually: ${KIBANA_URL}/app/security/alerts"
fi

echo ""
print_phase "Test Cycle Complete"
if [ "$ALERT_FOUND" = true ]; then
    print_info "SUCCESS: Exploit -> Alert -> Workflow pipeline is working"
    print_info "Check workflow execution: ${KIBANA_URL}/app/management/insightsAndAlerting/workflows"
else
    print_warn "Alert did not fire within the timeout. Debug steps:"
    print_warn "  1. Check process events: curl ES for logs-endpoint.events.process-* with parent=java"
    print_warn "  2. Check rule status in Kibana Security -> Rules"
    print_warn "  3. Check agent status: ssh into solr-kb, run 'sudo elastic-agent status'"
fi

################################################################################
# STEP 8: Launch interactive attacker session
################################################################################

print_phase "STEP 8: Launching interactive attacker session"

print_info "Running exploit again with interactive reverse shell..."
print_info "You will be dropped into a shell on the target. Type 'exit' or Ctrl+C to disconnect."
echo ""

ssh -t $SSH_OPTS "$SSH_USER@$REDTEAM_PUBLIC_IP" \
    "bash /home/ubuntu/scripts/host-scan.sh -t $SOLR_KB_PRIVATE_IP -a $REDTEAM_PRIVATE_IP"
