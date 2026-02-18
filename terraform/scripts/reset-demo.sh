#!/bin/bash

################################################################################
# SIEM Demo - Soft Reset for Practice Runs
#
# Quickly resets the demo environment WITHOUT recreating VMs:
#   1. Kills attacker processes (msfconsole, listeners)
#   2. Kills victim reverse shells (does NOT restart Solr — see note below)
#   3. Deletes Elastic Security alerts for our detection rule
#   4. Resets detection rule alert suppression (disable/re-enable)
#   5. Deletes Elastic Security cases created by the workflow
#   6. Verifies readiness (Solr up, Agent healthy, events flowing)
#
# NOTE: We intentionally do NOT restart Solr. Restarting creates a new Java
# PID which invalidates Elastic Defend's process tree cache, causing a
# monitoring gap where the next exploit's shell-from-java event won't be
# captured and the detection rule won't fire. The exploit doesn't modify
# Solr, so a restart is unnecessary.
#
# Takes ~30 seconds vs ~5 minutes for the full VM recreation
# (reset-solr-red-vm.sh).
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/reset-demo.sh
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
AUTH="${ES_USER}:${ES_PASS}"

REDTEAM_PUBLIC_IP=$(terraform output -raw redteam_public_ip)
REDTEAM_PRIVATE_IP=$(terraform output -raw redteam_private_ip)

SOLR_KB_PUBLIC_IP=$(terraform output -json host_public_ips | jq -r '.["solr-kb"]')
SOLR_KB_PRIVATE_IP=$(terraform output -json host_private_ips | jq -r '.["solr-kb"]')

print_info "Kibana:          $KIBANA_URL"
print_info "solr-kb public:  $SOLR_KB_PUBLIC_IP"
print_info "solr-kb private: $SOLR_KB_PRIVATE_IP"
print_info "attacker public: $REDTEAM_PUBLIC_IP"
print_info "attacker private: $REDTEAM_PRIVATE_IP"

################################################################################
# STEP 2: Clean up attacker VM
################################################################################

print_phase "STEP 2: Cleaning up attacker VM"

print_info "Killing msfconsole and listeners on attacker..."
ssh $SSH_OPTS "$SSH_USER@$REDTEAM_PUBLIC_IP" bash << 'EOSSH'
# Kill all Metasploit processes
sudo pkill -f msfconsole 2>/dev/null || true
sudo pkill -f msfrpcd 2>/dev/null || true

# Kill any listeners on exploit ports (LDAP 1389, HTTP 8080, shell 4444/4445)
for port in 4444 4445 1389 8080; do
    sudo fuser -k ${port}/tcp 2>/dev/null || true
done

# Clean up temp files from previous runs
rm -f /tmp/host-scan.rc /home/ubuntu/scripts/host-scan.rc 2>/dev/null || true

echo "Attacker cleanup done."
EOSSH
print_info "Attacker VM cleaned."

################################################################################
# STEP 3: Clean up victim VM (solr-kb)
################################################################################

print_phase "STEP 3: Cleaning up victim VM (solr-kb)"

print_info "Killing reverse shells on solr-kb..."
ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" bash << 'EOSSH'
# Kill any reverse shell processes (shells whose parent is java)
# Do NOT restart Solr — the exploit doesn't modify it, and restarting
# creates a new Java PID that invalidates Elastic Defend's process tree
# cache, causing a monitoring gap where the next exploit's shell-from-java
# event won't be captured.
KILLED=0
for pid in $(ps -eo pid,ppid,comm --no-headers 2>/dev/null | awk '$3 ~ /^(sh|bash|dash)$/ { print $1, $2 }' | while read p pp; do
    if ps -p "$pp" -o comm= 2>/dev/null | grep -q java; then echo "$p"; fi
done); do
    sudo kill -9 "$pid" 2>/dev/null && KILLED=$((KILLED + 1)) || true
done

# Also kill any shells with network connections to attacker ports
for pid in $(sudo ss -tnp 2>/dev/null | grep -E ':(4444|4445) ' | grep -oP 'pid=\K[0-9]+' || true); do
    sudo kill -9 "$pid" 2>/dev/null && KILLED=$((KILLED + 1)) || true
done

echo "Killed ${KILLED} reverse shell process(es)."
EOSSH

# Verify Solr is still running (it should be — we didn't restart it)
SOLR_RESTARTED=false
if ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "curl -s http://localhost:8983/solr/ > /dev/null 2>&1"; then
    print_info "Solr is running (no restart needed)."
else
    print_warn "Solr is not responding — restarting..."
    ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo systemctl restart solr" 2>/dev/null || true
    SOLR_RESTARTED=true
    for i in $(seq 1 12); do
        if ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "curl -s http://localhost:8983/solr/ > /dev/null 2>&1"; then
            print_info "Solr is back up."
            break
        fi
        if [ "$i" -eq 12 ]; then
            print_warn "Solr not responding after 60s — continuing anyway."
        fi
        sleep 5
    done
fi

# If Solr was restarted (here or previously), the Elastic Agent's Defend
# integration loses track of the new Java process tree — it will never
# capture shell-from-java events until the agent is also restarted.
# Detect this by checking if recent java-parented process events exist.
if [ "$SOLR_RESTARTED" = false ]; then
    print_info "Checking Defend can see Java process tree..."
    JAVA_EVENTS=$(curl -sk -u "${AUTH}" \
        -H "Content-Type: application/json" \
        "${ES_URL}/logs-endpoint.events.process-*/_count" \
        -d "{
            \"query\": {
                \"bool\": {
                    \"filter\": [
                        {\"range\": {\"@timestamp\": {\"gte\": \"now-30m\"}}},
                        {\"term\": {\"host.name\": \"siem-demo-solr-kb\"}},
                        {\"term\": {\"process.parent.name\": \"java\"}},
                        {\"term\": {\"event.type\": \"start\"}}
                    ]
                }
            }
        }" 2>/dev/null | jq -r '.count // 0' 2>/dev/null)

    # Get the Java PID and the ENDPOINT SENSOR's start time to detect stale tracking.
    # ElasticEndpoint.service is the eBPF sensor that owns the process tree cache —
    # it's separate from elastic-agent.service and must be compared against Java.
    JAVA_PID=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "pgrep -f 'start.jar' -o 2>/dev/null || echo 0")
    ENDPOINT_PID=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "pgrep -f 'elastic-endpoint' -o 2>/dev/null || echo 0")

    if [ "$JAVA_PID" != "0" ] && [ "$ENDPOINT_PID" != "0" ]; then
        # If Java started AFTER the endpoint sensor, the sensor's process tree is stale
        JAVA_START=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "stat -c %Y /proc/$JAVA_PID 2>/dev/null || echo 0")
        ENDPOINT_START=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "stat -c %Y /proc/$ENDPOINT_PID 2>/dev/null || echo 0")

        if [ "$JAVA_START" -gt "$ENDPOINT_START" ] 2>/dev/null; then
            print_warn "Java (PID $JAVA_PID) started AFTER ElasticEndpoint (PID $ENDPOINT_PID) — process tree is stale."
            SOLR_RESTARTED=true
        else
            print_info "Java started before endpoint sensor — process tree tracking OK."
        fi
    fi
fi

if [ "$SOLR_RESTARTED" = true ]; then
    # ElasticEndpoint.service is a SEPARATE systemd service from elastic-agent.
    # Restarting elastic-agent does NOT restart the endpoint sensor. The endpoint
    # sensor owns the eBPF hooks and process tree cache — it must be restarted
    # directly so it re-scans /proc and learns the new Java PID.
    # See: https://github.com/elastic/elastic-agent/issues/2318
    #      https://github.com/elastic/ebpf/issues/155
    print_warn "Restarting ElasticEndpoint.service to rebuild process tree cache..."
    ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo systemctl restart ElasticEndpoint.service" 2>/dev/null || true

    # Also restart elastic-agent to keep it in sync with the endpoint
    print_info "Restarting elastic-agent.service..."
    ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo systemctl restart elastic-agent.service" 2>/dev/null || true

    print_info "Waiting for Elastic Agent + Defend to initialize..."
    for i in $(seq 1 24); do
        AGENT_STATUS=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo elastic-agent status 2>&1" || echo "error")
        if echo "$AGENT_STATUS" | grep -q "endpoint" && echo "$AGENT_STATUS" | grep -qi "HEALTHY.*Running"; then
            print_info "Agent and Defend are healthy."
            break
        fi
        if [ "$i" -eq 24 ]; then
            print_warn "Agent not fully healthy after 120s — continuing."
        fi
        sleep 5
    done

    # Verify the endpoint sensor now knows about the Java process
    print_info "Verifying endpoint sensor tracks Java process..."
    ENDPOINT_PID=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "pgrep -f 'elastic-endpoint' -o 2>/dev/null || echo 0")
    JAVA_PID_NOW=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "pgrep -f 'start.jar' -o 2>/dev/null || echo 0")
    if [ "$ENDPOINT_PID" != "0" ] && [ "$JAVA_PID_NOW" != "0" ]; then
        EP_START=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "stat -c %Y /proc/$ENDPOINT_PID 2>/dev/null || echo 0")
        JAVA_START_NOW=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "stat -c %Y /proc/$JAVA_PID_NOW 2>/dev/null || echo 0")
        if [ "$EP_START" -gt "$JAVA_START_NOW" ] 2>/dev/null; then
            print_info "Endpoint sensor (PID $ENDPOINT_PID) started AFTER Java (PID $JAVA_PID_NOW) — process tree tracking OK."
        else
            print_warn "Endpoint sensor started before Java — process tree may still be stale."
        fi
    fi

    # Wait for process events to start flowing
    print_info "Waiting for process event collection to resume..."
    for i in $(seq 1 12); do
        COUNT=$(curl -sk -u "${AUTH}" \
            -H "Content-Type: application/json" \
            "${ES_URL}/logs-endpoint.events.process-*/_count" \
            -d '{
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": "now-1m"}}},
                            {"term": {"host.name": "siem-demo-solr-kb"}}
                        ]
                    }
                }
            }' 2>/dev/null | jq -r '.count // 0' 2>/dev/null)
        if [ "$COUNT" -gt 0 ] 2>/dev/null; then
            print_info "Process events flowing ($COUNT in last minute)."
            break
        fi
        sleep 5
    done
fi

################################################################################
# STEP 4: Delete Elastic Security alerts
################################################################################

print_phase "STEP 4: Clearing Elastic Security alerts"

RULE_NAME="Shell Spawned by Java Process"

print_info "Deleting alerts for rule '${RULE_NAME}'..."
DELETE_RESPONSE=$(curl -sk -u "${AUTH}" \
    -X POST \
    -H "Content-Type: application/json" \
    "${ES_URL}/.alerts-security.alerts-default/_delete_by_query?refresh=true" \
    -d "{
        \"query\": {
            \"term\": {
                \"kibana.alert.rule.name\": \"${RULE_NAME}\"
            }
        }
    }" 2>/dev/null)

DELETED=$(echo "$DELETE_RESPONSE" | jq -r '.deleted // 0' 2>/dev/null)
print_info "Deleted ${DELETED} alert(s)."

################################################################################
# STEP 5: Reset detection rule (clear alert suppression state)
################################################################################

print_phase "STEP 5: Resetting detection rule suppression"

STABLE_RULE_ID="siem-demo-shell-spawned-by-java"

# Find the rule's internal ID
RULE_INTERNAL_ID=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/detection_engine/rules?rule_id=${STABLE_RULE_ID}" 2>/dev/null \
    | jq -r '.id // empty' 2>/dev/null)

if [ -n "$RULE_INTERNAL_ID" ]; then
    # Disable the rule
    print_info "Disabling detection rule..."
    curl -sk -u "${AUTH}" \
        -X PATCH \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/detection_engine/rules" \
        -d "{\"id\": \"${RULE_INTERNAL_ID}\", \"enabled\": false}" > /dev/null 2>&1

    sleep 2

    # Re-enable the rule (resets suppression window)
    print_info "Re-enabling detection rule..."
    curl -sk -u "${AUTH}" \
        -X PATCH \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/detection_engine/rules" \
        -d "{\"id\": \"${RULE_INTERNAL_ID}\", \"enabled\": true}" > /dev/null 2>&1

    print_info "Detection rule reset."
else
    print_warn "Detection rule '${STABLE_RULE_ID}' not found — skipping."
fi

################################################################################
# STEP 6: Delete Elastic Security cases
################################################################################

print_phase "STEP 6: Clearing Elastic Security cases"

CASE_IDS=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/cases/_find?perPage=100" 2>/dev/null \
    | jq -r '.cases[]?.id // empty' 2>/dev/null || echo "")

if [ -z "$CASE_IDS" ]; then
    print_info "No cases found."
else
    IDS_JSON=$(echo "$CASE_IDS" | jq -R . | jq -s -c .)
    IDS_ENCODED=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$IDS_JSON")
    COUNT=$(echo "$CASE_IDS" | wc -l | tr -d ' ')
    print_info "Deleting ${COUNT} case(s)..."

    HTTP_CODE=$(curl -sk -u "${AUTH}" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -o /dev/null -w "%{http_code}" \
        "${KIBANA_URL}/api/cases?ids=${IDS_ENCODED}" 2>/dev/null)

    if [ "$HTTP_CODE" = "204" ]; then
        print_info "Deleted ${COUNT} case(s)."
    else
        print_warn "Case deletion returned HTTP ${HTTP_CODE}."
    fi
fi

################################################################################
# STEP 7: Verify readiness
################################################################################

print_phase "STEP 7: Verifying readiness"

# Check Elastic Agent is healthy
print_info "Checking Elastic Agent status on solr-kb..."
AGENT_STATUS=$(ssh $SSH_OPTS "$SSH_USER@$SOLR_KB_PUBLIC_IP" "sudo elastic-agent status 2>&1 | head -5" || echo "error")
if echo "$AGENT_STATUS" | grep -qi "healthy"; then
    print_info "Agent is healthy."
else
    print_warn "Agent status: $(echo "$AGENT_STATUS" | head -1)"
fi

# Check process events are still flowing
print_info "Checking for recent process events from solr-kb..."
COUNT=$(curl -sk -u "${AUTH}" \
    -H "Content-Type: application/json" \
    "${ES_URL}/logs-endpoint.events.process-*/_count" \
    -d '{
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-2m"}}},
                    {"term": {"host.name": "siem-demo-solr-kb"}}
                ]
            }
        }
    }' 2>/dev/null | jq -r '.count // 0' 2>/dev/null)

if [ "$COUNT" -gt 0 ] 2>/dev/null; then
    print_info "Found $COUNT process events in last 2 minutes — collection active."
else
    print_warn "No recent process events — agent may need a moment to resume."
fi

################################################################################
# Ready
################################################################################

print_phase "Demo Reset Complete"

print_info "Environment is ready for the next demo run."
echo ""
print_info "Run the attack with:"
echo ""
echo "  ssh -t -i state/ssh-key.pem ubuntu@${REDTEAM_PUBLIC_IP} \\"
echo "    \"bash /home/ubuntu/scripts/host-scan.sh -t ${SOLR_KB_PRIVATE_IP} -a ${REDTEAM_PRIVATE_IP}\""
echo ""
