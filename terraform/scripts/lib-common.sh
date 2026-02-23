#!/bin/bash
################################################################################
# lib-common.sh — Shared functions for SIEM demo scripts
#
# Source this file at the top of any demo script:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-common.sh"
################################################################################

# --- Colors & output helpers -------------------------------------------------

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
print_phase() {
    echo -e "\n${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}\n"
}

# --- Path setup --------------------------------------------------------------

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$LIB_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"
SSH_KEY="${PROJECT_DIR}/state/ssh-key.pem"
SSH_USER="ubuntu"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

# --- Curl auth (hides credentials from process table) ------------------------
#
# Writes credentials to a temp file and uses curl -K (--config) instead of
# passing -u user:pass on the command line (visible in `ps aux`).

CURL_AUTH_CONF=""

# Usage: setup_curl_auth <username> <password>
setup_curl_auth() {
    CURL_AUTH_CONF=$(mktemp "${TMPDIR:-/tmp}/curl-auth-XXXXXX")
    chmod 600 "$CURL_AUTH_CONF"
    printf 'user = "%s:%s"\n' "$1" "$2" > "$CURL_AUTH_CONF"
}

cleanup_curl_auth() {
    [[ -n "$CURL_AUTH_CONF" ]] && rm -f "$CURL_AUTH_CONF"
    CURL_AUTH_CONF=""
}

# --- Terraform output helpers ------------------------------------------------

# Read common terraform outputs into global variables and set up curl auth.
# Sets: KIBANA_URL, ES_URL, ES_USER, ES_PASS, ES_VERSION, CURL_AUTH_CONF
read_terraform_outputs() {
    cd "$TERRAFORM_DIR"
    KIBANA_URL=$(terraform output -raw kibana_endpoint)
    ES_URL=$(terraform output -raw elasticsearch_endpoint)
    ES_USER=$(terraform output -raw elasticsearch_username)
    ES_PASS=$(terraform output -raw elasticsearch_password)
    ES_VERSION=$(terraform output -raw deployment_version)
    setup_curl_auth "$ES_USER" "$ES_PASS"
}

# Read solr-kb and red team VM IPs.
# Sets: REDTEAM_PUBLIC_IP, REDTEAM_PRIVATE_IP, SOLR_KB_PUBLIC_IP, SOLR_KB_PRIVATE_IP
read_vm_ips() {
    cd "$TERRAFORM_DIR"
    REDTEAM_PUBLIC_IP=$(terraform output -raw redteam_public_ip)
    REDTEAM_PRIVATE_IP=$(terraform output -raw redteam_private_ip)
    SOLR_KB_PUBLIC_IP=$(terraform output -json host_public_ips | jq -r '.["solr-kb"]')
    SOLR_KB_PRIVATE_IP=$(terraform output -json host_private_ips | jq -r '.["solr-kb"]')
}

print_vm_ips() {
    print_info "Kibana:          $KIBANA_URL"
    print_info "solr-kb public:  $SOLR_KB_PUBLIC_IP"
    print_info "solr-kb private: $SOLR_KB_PRIVATE_IP"
    print_info "attacker public: $REDTEAM_PUBLIC_IP"
    print_info "attacker private: $REDTEAM_PRIVATE_IP"
}

# --- VM lifecycle functions ---------------------------------------------------

# Taint and recreate solr-kb, then re-read IPs.
recreate_solr_kb() {
    cd "$TERRAFORM_DIR"
    print_info "Tainting aws_instance.host[0] (solr-kb)..."
    terraform taint 'aws_instance.host[0]'

    print_info "Running terraform apply..."
    terraform apply --auto-approve -target='aws_instance.host[0]' 2>&1

    # Re-read IPs (they change on recreate)
    SOLR_KB_PUBLIC_IP=$(terraform output -json host_public_ips | jq -r '.["solr-kb"]')
    SOLR_KB_PRIVATE_IP=$(terraform output -json host_private_ips | jq -r '.["solr-kb"]')
    print_info "New solr-kb public IP:  $SOLR_KB_PUBLIC_IP"
    print_info "New solr-kb private IP: $SOLR_KB_PRIVATE_IP"
}

# Wait for SSH, cloud-init, and Solr on solr-kb.
wait_for_solr_kb() {
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
            return 0
        fi
        sleep 5
    done
    print_warn "Solr may not be running yet — continuing anyway"
}

# Install Elastic Agent on solr-kb using Fleet API.
install_agent_solr_kb() {
    # Get Fleet URL
    FLEET_URL=$(curl -s -K "$CURL_AUTH_CONF" \
        --header "kbn-xsrf: true" \
        "${KIBANA_URL}/api/fleet/fleet_server_hosts" \
        | jq -r '.items[] | select(.is_default==true) | .host_urls[0]')

    if [ -z "$FLEET_URL" ] || [ "$FLEET_URL" = "null" ]; then
        print_error "Could not get Fleet Server URL"
        exit 1
    fi

    # Get policy ID
    local policy_name="SIEM Demo - Endpoint Security"
    POLICY_ID=$(curl -s -K "$CURL_AUTH_CONF" \
        --header "kbn-xsrf: true" \
        "${KIBANA_URL}/api/fleet/agent_policies" \
        | jq -r ".items[] | select(.name==\"${policy_name}\") | .id")

    if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
        print_error "Agent policy '${policy_name}' not found. Run deploy-elastic-agent.sh first."
        exit 1
    fi

    # Get enrollment token
    ENROLLMENT_TOKEN=$(curl -s -K "$CURL_AUTH_CONF" \
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
}

# Wait for process events to appear in Elasticsearch from solr-kb.
wait_for_process_events() {
    print_info "Waiting up to 3 minutes for process events from siem-demo-solr-kb..."
    local events_found=false
    for i in $(seq 1 36); do
        COUNT=$(curl -s -K "$CURL_AUTH_CONF" \
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
            events_found=true
            break
        fi
        [ $((i % 6)) -eq 0 ] && print_info "  Still waiting... ($((i * 5))s elapsed)"
        sleep 5
    done

    if [ "$events_found" = false ]; then
        print_warn "No process events yet after 3 minutes — proceeding anyway"
    fi

    # Extra stabilisation wait
    print_info "Waiting 30s for event pipeline to stabilise..."
    sleep 30
}
