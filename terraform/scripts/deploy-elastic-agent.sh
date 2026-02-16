#!/bin/bash

################################################################################
# SIEM Workflow Demo - Elastic Agent Deployment Script
#
# Deploys Elastic Agent with Defend and osquery integrations to all 3 host VMs.
#
# Prerequisites:
#   - Elastic Cloud deployment is running (terraform apply completed)
#   - Host VMs are provisioned and cloud-init has completed
#   - Terraform outputs are available
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/deploy-elastic-agent.sh
#
# The script reads all needed values from terraform outputs automatically.
################################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"

################################################################################
# READ TERRAFORM OUTPUTS
################################################################################

echo "=========================================="
echo "Elastic Agent Deployment - SIEM Demo Hosts"
echo "=========================================="
echo ""

print_step "Reading Terraform outputs..."

cd "$TERRAFORM_DIR"

KIBANA_URL=$(terraform output -raw kibana_endpoint)
ELASTIC_USER=$(terraform output -raw elasticsearch_username)
ELASTIC_PASSWORD=$(terraform output -raw elasticsearch_password)
ELASTICSEARCH_URL=$(terraform output -raw elasticsearch_endpoint)
ELASTIC_VERSION=$(terraform output -raw deployment_version)
DEPLOYMENT_ID=$(terraform output -raw deployment_id)
SSH_KEY="${PROJECT_DIR}/state/ssh-key.pem"
SSH_USER="ubuntu"
POLICY_NAME="SIEM Demo - Endpoint Security"

# Get host IPs as JSON, then extract
HOST_PUBLIC_IPS_JSON=$(terraform output -json host_public_ips)
HOST_PRIVATE_IPS_JSON=$(terraform output -json host_private_ips)

HOST_COUNT=$(echo "$HOST_PUBLIC_IPS_JSON" | jq 'length')

cd "$PROJECT_DIR"

# Get Fleet Server URL from Kibana API (not from terraform - the integrations_server
# endpoint is the APM server, not Fleet Server)
print_info "Fetching Fleet Server URL from Kibana..."
FLEET_URL=$(curl -s --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
  --header "kbn-xsrf: true" \
  "${KIBANA_URL}/api/fleet/fleet_server_hosts" \
  | jq -r '.items[] | select(.is_default==true) | .host_urls[0]')

if [ -z "$FLEET_URL" ] || [ "$FLEET_URL" = "null" ]; then
    print_error "Could not determine Fleet Server URL from Kibana"
    exit 1
fi

print_info "Configuration:"
echo "  Kibana URL:      $KIBANA_URL"
echo "  Fleet URL:       $FLEET_URL"
echo "  Elastic Version: $ELASTIC_VERSION"
echo "  SSH Key:         $SSH_KEY"
echo "  Hosts to deploy: $HOST_COUNT"
for HOST_KEY in $(echo "$HOST_PUBLIC_IPS_JSON" | jq -r 'keys[]'); do
    PUB_IP=$(echo "$HOST_PUBLIC_IPS_JSON" | jq -r ".[\"${HOST_KEY}\"]")
    PRIV_IP=$(echo "$HOST_PRIVATE_IPS_JSON" | jq -r ".[\"${HOST_KEY}\"]")
    echo "    ${HOST_KEY}: ${PUB_IP} (private: ${PRIV_IP})"
done
echo ""

################################################################################
# STEP 1: Create Agent Policy
################################################################################

print_step "[1/5] Creating agent policy..."

# Check if policy already exists
EXISTING_POLICIES=$(curl -s --request GET \
  --url "${KIBANA_URL}/api/fleet/agent_policies" \
  --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
  --header "kbn-xsrf: true")

POLICY_ID=$(echo "$EXISTING_POLICIES" | jq -r ".items[] | select(.name==\"${POLICY_NAME}\") | .id")

if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
    print_info "Using existing agent policy: $POLICY_ID"
else
    POLICY_RESPONSE=$(curl -s --request POST \
      --url "${KIBANA_URL}/api/fleet/agent_policies?sys_monitoring=true" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "Content-Type: application/json" \
      --header "kbn-xsrf: true" \
      --data '{
        "name": "'"${POLICY_NAME}"'",
        "namespace": "default",
        "description": "Policy for SIEM demo host VMs with Defend and osquery integrations",
        "monitoring_enabled": ["logs", "metrics"]
      }')

    POLICY_ID=$(echo "$POLICY_RESPONSE" | jq -r '.item.id')

    if [ -z "$POLICY_ID" ] || [ "$POLICY_ID" = "null" ]; then
        print_error "Failed to create agent policy"
        echo "Response: $POLICY_RESPONSE"
        exit 1
    fi

    print_info "Agent policy created: $POLICY_ID"
fi

echo ""

################################################################################
# STEP 2: Add Elastic Defend Integration (3-step process)
################################################################################

print_step "[2/5] Adding Elastic Defend integration..."

# Check if Defend is already on this policy
EXISTING_PACKAGES=$(curl -s --request GET \
  --url "${KIBANA_URL}/api/fleet/package_policies?perPage=100" \
  --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
  --header "kbn-xsrf: true")

DEFEND_EXISTS=$(echo "$EXISTING_PACKAGES" | jq -r ".items[] | select(.policy_id==\"${POLICY_ID}\" and .package.name==\"endpoint\") | .id")

if [ -n "$DEFEND_EXISTS" ] && [ "$DEFEND_EXISTS" != "null" ]; then
    print_info "Elastic Defend already configured on this policy"
    PACKAGE_POLICY_ID="$DEFEND_EXISTS"
else
    PACKAGE_VERSION=$(echo "$ELASTIC_VERSION" | cut -d. -f1,2).0

    # Step 2a: Create with default settings (EDRComplete preset)
    print_info "  [a] Creating Elastic Defend with EDRComplete preset..."
    DEFEND_RESPONSE=$(curl -s --request POST \
      --url "${KIBANA_URL}/api/fleet/package_policies" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "Content-Type: application/json" \
      --header "kbn-xsrf: true" \
      --header "kbn-version: ${ELASTIC_VERSION}" \
      --data '{
        "name": "Elastic Defend - Detect Mode",
        "description": "Defend integration in detect mode with full event collection",
        "namespace": "default",
        "policy_id": "'"${POLICY_ID}"'",
        "enabled": true,
        "inputs": [
          {
            "enabled": true,
            "streams": [],
            "type": "ENDPOINT_INTEGRATION_CONFIG",
            "config": {
              "_config": {
                "value": {
                  "type": "endpoint",
                  "endpointConfig": {
                    "preset": "EDRComplete"
                  }
                }
              }
            }
          }
        ],
        "package": {
          "name": "endpoint",
          "title": "Elastic Defend",
          "version": "'"${PACKAGE_VERSION}"'"
        }
      }')

    PACKAGE_POLICY_ID=$(echo "$DEFEND_RESPONSE" | jq -r '.item.id')

    if [ -z "$PACKAGE_POLICY_ID" ] || [ "$PACKAGE_POLICY_ID" = "null" ]; then
        print_error "Failed to create Defend integration"
        echo "Response: $DEFEND_RESPONSE"
        exit 1
    fi

    print_info "  Defend integration created: $PACKAGE_POLICY_ID"

    # Step 2b: GET current config
    print_info "  [b] Retrieving current Defend configuration..."
    CURRENT_CONFIG=$(curl -s --request GET \
      --url "${KIBANA_URL}/api/fleet/package_policies/${PACKAGE_POLICY_ID}" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "kbn-xsrf: true" \
      --header "kbn-version: ${ELASTIC_VERSION}")

    # Step 2c: PUT to update to detect mode with full Linux event collection
    print_info "  [c] Updating to detect mode with full event collection..."
    UPDATE_RESPONSE=$(curl -s --request PUT \
      --url "${KIBANA_URL}/api/fleet/package_policies/${PACKAGE_POLICY_ID}" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "Content-Type: application/json" \
      --header "kbn-xsrf: true" \
      --header "kbn-version: ${ELASTIC_VERSION}" \
      --data '{
        "name": "Elastic Defend - Detect Mode",
        "namespace": "default",
        "policy_id": "'"${POLICY_ID}"'",
        "enabled": true,
        "package": {
          "name": "endpoint",
          "title": "Elastic Defend",
          "version": "'"${PACKAGE_VERSION}"'"
        },
        "inputs": [
          {
            "type": "endpoint",
            "enabled": true,
            "streams": [],
            "config": {
              "policy": {
                "value": {
                  "linux": {
                    "events": {
                      "process": true,
                      "network": true,
                      "file": true,
                      "session_data": true,
                      "tty_io": true
                    },
                    "malware": { "mode": "detect" },
                    "behavior_protection": { "mode": "detect" },
                    "memory_protection": { "mode": "detect" }
                  },
                  "windows": {
                    "events": {
                      "process": true,
                      "network": true,
                      "file": true,
                      "registry": true,
                      "security": true,
                      "dll_and_driver_load": true,
                      "dns": true
                    },
                    "malware": { "mode": "detect" },
                    "ransomware": { "mode": "detect" },
                    "memory_protection": { "mode": "detect" },
                    "behavior_protection": { "mode": "detect" }
                  },
                  "mac": {
                    "events": {
                      "process": true,
                      "network": true,
                      "file": true
                    },
                    "malware": { "mode": "detect" },
                    "behavior_protection": { "mode": "detect" },
                    "memory_protection": { "mode": "detect" }
                  }
                }
              }
            }
          }
        ]
      }')

    UPDATE_SUCCESS=$(echo "$UPDATE_RESPONSE" | jq -r '.success')
    if [ "$UPDATE_SUCCESS" != "true" ]; then
        print_warn "Detect mode update may have failed, continuing..."
    else
        print_info "  Defend configured: detect mode, full event collection"
    fi
fi

print_info "Elastic Defend integration ready"
echo ""

################################################################################
# STEP 3: Add osquery Manager Integration
################################################################################

print_step "[3/5] Adding osquery Manager integration..."

OSQUERY_EXISTS=$(echo "$EXISTING_PACKAGES" | jq -r ".items[] | select(.policy_id==\"${POLICY_ID}\" and .package.name==\"osquery_manager\") | .id")

if [ -n "$OSQUERY_EXISTS" ] && [ "$OSQUERY_EXISTS" != "null" ]; then
    print_info "osquery Manager already configured on this policy"
else
    # Get the latest osquery_manager package version
    print_info "  Fetching osquery_manager package info..."
    OSQUERY_PACKAGE_INFO=$(curl -s --request GET \
      --url "${KIBANA_URL}/api/fleet/epm/packages/osquery_manager" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "kbn-xsrf: true")

    OSQUERY_VERSION=$(echo "$OSQUERY_PACKAGE_INFO" | jq -r '.item.version // .response.version // "1.12.1"')
    print_info "  Using osquery_manager version: $OSQUERY_VERSION"

    # Install package if not already installed
    OSQUERY_INSTALLED=$(echo "$OSQUERY_PACKAGE_INFO" | jq -r '.item.status // .response.status // "not_installed"')
    if [ "$OSQUERY_INSTALLED" != "installed" ]; then
        print_info "  Installing osquery_manager package..."
        curl -s --request POST \
          --url "${KIBANA_URL}/api/fleet/epm/packages/osquery_manager/${OSQUERY_VERSION}" \
          --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
          --header "Content-Type: application/json" \
          --header "kbn-xsrf: true" \
          --data '{}' > /dev/null
        sleep 2
    fi

    # Add osquery integration to policy
    print_info "  Creating osquery Manager integration..."
    OSQUERY_RESPONSE=$(curl -s --request POST \
      --url "${KIBANA_URL}/api/fleet/package_policies" \
      --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
      --header "Content-Type: application/json" \
      --header "kbn-xsrf: true" \
      --data '{
        "name": "osquery Manager",
        "description": "osquery integration for live queries and scheduled packs",
        "namespace": "default",
        "policy_id": "'"${POLICY_ID}"'",
        "enabled": true,
        "inputs": [
          {
            "type": "osquery",
            "enabled": true,
            "streams": []
          }
        ],
        "package": {
          "name": "osquery_manager",
          "title": "Osquery Manager",
          "version": "'"${OSQUERY_VERSION}"'"
        }
      }')

    OSQUERY_POLICY_ID=$(echo "$OSQUERY_RESPONSE" | jq -r '.item.id')

    if [ -z "$OSQUERY_POLICY_ID" ] || [ "$OSQUERY_POLICY_ID" = "null" ]; then
        print_warn "Failed to add osquery Manager integration"
        echo "Response: $OSQUERY_RESPONSE"
    else
        print_info "osquery Manager integration added: $OSQUERY_POLICY_ID"
    fi
fi

echo ""

################################################################################
# STEP 4: Get Enrollment Token
################################################################################

print_step "[4/5] Retrieving enrollment token..."

sleep 2

ENROLLMENT_RESPONSE=$(curl -s --request GET \
  --url "${KIBANA_URL}/api/fleet/enrollment_api_keys" \
  --user "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
  --header "kbn-xsrf: true")

ENROLLMENT_TOKEN=$(echo "$ENROLLMENT_RESPONSE" | jq -r ".items[] | select(.policy_id==\"${POLICY_ID}\") | .api_key")

if [ -z "$ENROLLMENT_TOKEN" ] || [ "$ENROLLMENT_TOKEN" = "null" ]; then
    print_error "Failed to retrieve enrollment token"
    echo "Response: $ENROLLMENT_RESPONSE"
    exit 1
fi

print_info "Enrollment token retrieved"
echo ""

################################################################################
# STEP 5: Deploy Agent to All Host VMs
################################################################################

print_step "[5/5] Deploying Elastic Agent to ${HOST_COUNT} host VMs..."
echo ""

SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

for HOST_KEY in $(echo "$HOST_PUBLIC_IPS_JSON" | jq -r 'keys[]'); do
    HOST_IP=$(echo "$HOST_PUBLIC_IPS_JSON" | jq -r ".[\"${HOST_KEY}\"]")

    echo "  ----------------------------------------"
    print_info "Deploying to ${HOST_KEY} (${HOST_IP})..."

    # Wait for SSH
    print_info "  Waiting for SSH access..."
    MAX_ATTEMPTS=30
    CONNECTED=false
    for attempt in $(seq 1 $MAX_ATTEMPTS); do
        if ssh $SSH_OPTS "$SSH_USER@$HOST_IP" "echo ok" > /dev/null 2>&1; then
            CONNECTED=true
            break
        fi
        if [ $((attempt % 5)) -eq 0 ]; then
            print_info "  SSH attempt $attempt/$MAX_ATTEMPTS..."
        fi
        sleep 10
    done

    if [ "$CONNECTED" = false ]; then
        print_error "  Cannot connect to ${HOST_KEY} via SSH, skipping"
        continue
    fi

    # Wait for cloud-init
    print_info "  Waiting for cloud-init to complete..."
    ssh $SSH_OPTS "$SSH_USER@$HOST_IP" "cloud-init status --wait" > /dev/null 2>&1 || true

    # Download, extract, install agent
    print_info "  Installing Elastic Agent ${ELASTIC_VERSION}..."
    ssh $SSH_OPTS "$SSH_USER@$HOST_IP" bash << EOSSH
set -e

cd /tmp

# Download agent if not already present
if [ ! -f "elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz" ]; then
    echo "Downloading Elastic Agent ${ELASTIC_VERSION}..."
    curl -sL -O "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"
fi

# Extract
echo "Extracting..."
tar xzf "elastic-agent-${ELASTIC_VERSION}-linux-x86_64.tar.gz"

# Install and enroll
echo "Installing and enrolling agent..."
cd "elastic-agent-${ELASTIC_VERSION}-linux-x86_64"
sudo ./elastic-agent install \
  --url="${FLEET_URL}" \
  --enrollment-token="${ENROLLMENT_TOKEN}" \
  --force \
  --non-interactive

echo "Agent installation completed on \$(hostname)"
EOSSH

    # Verify
    sleep 3
    AGENT_STATUS=$(ssh $SSH_OPTS "$SSH_USER@$HOST_IP" "sudo elastic-agent status 2>&1" || echo "error")

    if echo "$AGENT_STATUS" | grep -q "healthy"; then
        print_info "  ${HOST_KEY}: Agent is healthy"
    elif echo "$AGENT_STATUS" | grep -q "online"; then
        print_info "  ${HOST_KEY}: Agent is online"
    else
        print_warn "  ${HOST_KEY}: Agent status unclear - check Fleet UI"
    fi

    echo ""
done

################################################################################
# COMPLETION
################################################################################

echo "=========================================="
echo "Elastic Agent Deployment Complete!"
echo "=========================================="
echo ""

print_info "Summary:"
echo "  Policy:  $POLICY_NAME ($POLICY_ID)"
echo "  Version: $ELASTIC_VERSION"
echo ""
echo "  Integrations configured:"
echo "    - System (logs & metrics)"
echo "    - Elastic Defend (EDR Complete, detect mode, full event collection)"
echo "    - osquery Manager (live queries and scheduled packs)"
echo ""
echo "  Index patterns covered:"
echo "    - logs-endpoint.events.process*  (Defend)"
echo "    - logs-endpoint.events.network*  (Defend)"
echo "    - logs-endpoint.events.file*     (Defend)"
echo "    - logs-system.*                  (System)"
echo ""

print_info "Fleet UI: ${KIBANA_URL}/app/fleet/agents"
print_info "Security: ${KIBANA_URL}/app/security"
echo ""

print_info "Verify agent status on any host:"
echo "  ssh $SSH_OPTS $SSH_USER@<HOST_IP> 'sudo elastic-agent status'"
echo ""

print_info "Run osquery live query from Kibana:"
echo "  ${KIBANA_URL}/app/osquery"
echo ""
