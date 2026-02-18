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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }
print_phase() { echo -e "\n${PURPLE}========================================${NC}"; echo -e "${PURPLE} $1${NC}"; echo -e "${PURPLE}========================================${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"
SSH_KEY="${PROJECT_DIR}/state/ssh-key.pem"
SSH_USER="ubuntu"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

cd "$TERRAFORM_DIR"

################################################################################
# STEP 1: Read terraform outputs
################################################################################

print_phase "STEP 1: Reading Terraform outputs"

KIBANA_URL=$(terraform output -raw kibana_endpoint)
ES_URL=$(terraform output -raw elasticsearch_endpoint)
ES_USER=$(terraform output -raw elasticsearch_username)
ES_PASS=$(terraform output -raw elasticsearch_password)
ES_VERSION=$(terraform output -raw deployment_version)
AUTH="${ES_USER}:${ES_PASS}"

REDTEAM_PUBLIC_IP=$(terraform output -json host_public_ips 2>/dev/null | jq -r 'empty' 2>/dev/null; terraform output -raw redteam_public_ip)
REDTEAM_PRIVATE_IP=$(terraform output -raw redteam_private_ip)

# solr-kb is index 0 in the host_configs list
SOLR_KB_PUBLIC_IP=$(terraform output -json host_public_ips | jq -r '.["solr-kb"]')
SOLR_KB_PRIVATE_IP=$(terraform output -json host_private_ips | jq -r '.["solr-kb"]')

print_info "Kibana:          $KIBANA_URL"
print_info "solr-kb public:  $SOLR_KB_PUBLIC_IP"
print_info "solr-kb private: $SOLR_KB_PRIVATE_IP"
print_info "attacker public: $REDTEAM_PUBLIC_IP"
print_info "attacker private: $REDTEAM_PRIVATE_IP"

################################################################################
# STEP 2: Taint and recreate solr-kb VM
################################################################################

print_phase "STEP 2: Recreating solr-kb VM"

print_info "Tainting aws_instance.host[0] (solr-kb)..."
terraform taint 'aws_instance.host[0]'

print_info "Running terraform apply..."
terraform apply --auto-approve -target='aws_instance.host[0]' 2>&1

# Re-read the new public IP (it changes on recreate)
SOLR_KB_PUBLIC_IP=$(terraform output -json host_public_ips | jq -r '.["solr-kb"]')
SOLR_KB_PRIVATE_IP=$(terraform output -json host_private_ips | jq -r '.["solr-kb"]')
print_info "New solr-kb public IP:  $SOLR_KB_PUBLIC_IP"
print_info "New solr-kb private IP: $SOLR_KB_PRIVATE_IP"

################################################################################
# STEP 3: Wait for cloud-init + Solr
################################################################################

print_phase "STEP 3: Waiting for cloud-init and Solr"

print_info "Waiting for SSH access..."
for attempt in $(seq 1 30); do
    if ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "echo ok" > /dev/null 2>&1; then
        print_info "SSH is up (attempt $attempt)"
        break
    fi
    [ $((attempt % 5)) -eq 0 ] && print_info "  SSH attempt $attempt/30..."
    sleep 10
done

print_info "Waiting for cloud-init to complete..."
ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "cloud-init status --wait" 2>&1 || true

print_info "Checking Solr is running..."
for i in $(seq 1 15); do
    if ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "curl -s http://localhost:8983/solr/ > /dev/null 2>&1"; then
        print_info "Solr is up!"
        break
    fi
    sleep 5
done

################################################################################
# STEP 4: Install Elastic Agent on solr-kb
################################################################################

print_phase "STEP 4: Installing Elastic Agent"

# Get Fleet URL
FLEET_URL=$(curl -s --user "${AUTH}" \
    --header "kbn-xsrf: true" \
    "${KIBANA_URL}/api/fleet/fleet_server_hosts" \
    | jq -r '.items[] | select(.is_default==true) | .host_urls[0]')

if [ -z "$FLEET_URL" ] || [ "$FLEET_URL" = "null" ]; then
    print_error "Could not get Fleet Server URL"
    exit 1
fi

# Get policy ID
POLICY_NAME="SIEM Demo - Endpoint Security"
POLICY_ID=$(curl -s --user "${AUTH}" \
    --header "kbn-xsrf: true" \
    "${KIBANA_URL}/api/fleet/agent_policies" \
    | jq -r ".items[] | select(.name==\"${POLICY_NAME}\") | .id")

if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
    print_error "Agent policy '${POLICY_NAME}' not found. Run deploy-elastic-agent.sh first."
    exit 1
fi

# Get enrollment token
ENROLLMENT_TOKEN=$(curl -s --user "${AUTH}" \
    --header "kbn-xsrf: true" \
    "${KIBANA_URL}/api/fleet/enrollment_api_keys" \
    | jq -r ".items[] | select(.policy_id==\"${POLICY_ID}\") | .api_key")

if [ -z "$ENROLLMENT_TOKEN" ] || [ "$ENROLLMENT_TOKEN" = "null" ]; then
    print_error "Could not get enrollment token"
    exit 1
fi

print_info "Fleet URL: $FLEET_URL"
print_info "Policy:    $POLICY_ID"

print_info "Installing Elastic Agent ${ES_VERSION} on solr-kb..."
ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" bash << EOSSH
set -e
cd /tmp
echo "Downloading Elastic Agent ${ES_VERSION}..."
curl -sL -O "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ES_VERSION}-linux-x86_64.tar.gz"
echo "Extracting..."
tar xzf "elastic-agent-${ES_VERSION}-linux-x86_64.tar.gz"
echo "Installing and enrolling..."
cd "elastic-agent-${ES_VERSION}-linux-x86_64"
sudo ./elastic-agent install \
    --url="${FLEET_URL}" \
    --enrollment-token="${ENROLLMENT_TOKEN}" \
    --force \
    --non-interactive
echo "Agent installed on \$(hostname)"
EOSSH

sleep 5
AGENT_STATUS=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo elastic-agent status 2>&1 | head -5" || echo "error")
echo "$AGENT_STATUS"
if echo "$AGENT_STATUS" | grep -qi "healthy"; then
    print_info "Agent is healthy"
else
    print_warn "Agent status unclear — continuing anyway"
fi

################################################################################
# STEP 5: Wait for event collection to start
################################################################################

print_phase "STEP 5: Waiting for process events to appear in Elasticsearch"

print_info "Waiting up to 3 minutes for process events from siem-demo-solr-kb..."
EVENTS_FOUND=false
for i in $(seq 1 36); do
    COUNT=$(curl -sk -u "${AUTH}" \
        -H "Content-Type: application/json" \
        "${ES_URL}/logs-endpoint.events.process-*/_count" \
        -d '{
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m"}}},
                        {"term": {"host.name": "siem-demo-solr-kb"}}
                    ]
                }
            }
        }' 2>/dev/null | jq -r '.count // 0' 2>/dev/null)

    if [ "$COUNT" -gt 0 ] 2>/dev/null; then
        print_info "Found $COUNT process events — event collection is active!"
        EVENTS_FOUND=true
        break
    fi
    [ $((i % 6)) -eq 0 ] && print_info "  Still waiting... ($((i * 5))s elapsed)"
    sleep 5
done

if [ "$EVENTS_FOUND" = false ]; then
    print_warn "No process events yet after 3 minutes — proceeding anyway"
fi

# Extra stabilisation wait
print_info "Waiting 30s for event pipeline to stabilise..."
sleep 30

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
    ALERT_COUNT=$(curl -sk -u "${AUTH}" \
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
