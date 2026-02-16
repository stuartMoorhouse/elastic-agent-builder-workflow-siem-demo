#!/bin/bash

################################################################################
# SIEM Workflow Demo - Agent Builder + Workflow Deployment Script
#
# Creates the Agent Builder agent, the reports index, and imports the
# workflow — all via Kibana and Elasticsearch APIs.
#
# Prerequisites:
#   - Elastic Cloud deployment is running (terraform apply completed)
#   - Elastic Agent deployed with Defend + osquery (deploy-elastic-agent.sh)
#   - Terraform outputs are available
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/deploy-workflow.sh
#
# The script reads Kibana URL and credentials from terraform outputs.
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
WORKFLOWS_DIR="${PROJECT_DIR}/workflows"

AGENT_DEF="${WORKFLOWS_DIR}/agents/security-analyst.json"
WORKFLOW_DEF="${WORKFLOWS_DIR}/defend-alert-triage.yaml"

################################################################################
# READ TERRAFORM OUTPUTS
################################################################################

echo "=========================================="
echo "Agent Builder + Workflow Deployment"
echo "=========================================="
echo ""

print_step "Reading Terraform outputs..."

cd "$TERRAFORM_DIR"

KIBANA_URL=$(terraform output -raw kibana_endpoint)
ES_URL=$(terraform output -raw elasticsearch_endpoint)
ES_USER=$(terraform output -raw elasticsearch_username)
ES_PASS=$(terraform output -raw elasticsearch_password)

AUTH="${ES_USER}:${ES_PASS}"

print_info "Kibana URL: ${KIBANA_URL}"
print_info "ES URL:     ${ES_URL}"
echo ""

# Verify connectivity
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" "${KIBANA_URL}/api/status" 2>/dev/null)
if [[ "$HTTP_CODE" != "200" ]]; then
    print_error "Cannot reach Kibana (HTTP ${HTTP_CODE}). Is the deployment running?"
    exit 1
fi
print_info "Kibana is reachable."

################################################################################
# STEP 1: Create the Agent Builder agent
################################################################################

print_step "[1/4] Creating Agent Builder agent..."

if [[ ! -f "$AGENT_DEF" ]]; then
    print_error "Agent definition not found: ${AGENT_DEF}"
    exit 1
fi

AGENT_NAME=$(jq -r '.name' "$AGENT_DEF")

# Check if agent already exists
EXISTING=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/agent_builder/agents" 2>/dev/null \
    | jq -r ".data[]? | select(.name == \"${AGENT_NAME}\") | .id" 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
    print_info "Agent '${AGENT_NAME}' already exists (ID: ${EXISTING}). Updating..."
    AGENT_RESPONSE=$(curl -sk -u "${AUTH}" \
        -X PUT \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/agent_builder/agents/${EXISTING}" \
        -d @"$AGENT_DEF" 2>/dev/null)
    AGENT_ID="$EXISTING"
else
    print_info "Creating agent '${AGENT_NAME}'..."
    AGENT_RESPONSE=$(curl -sk -u "${AUTH}" \
        -X POST \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/agent_builder/agents" \
        -d @"$AGENT_DEF" 2>/dev/null)
    AGENT_ID=$(echo "$AGENT_RESPONSE" | jq -r '.id // .data.id // empty' 2>/dev/null || echo "")
fi

if [[ -z "$AGENT_ID" ]]; then
    print_warn "Could not parse agent ID from response. Response:"
    echo "$AGENT_RESPONSE" | jq . 2>/dev/null || echo "$AGENT_RESPONSE"
    print_warn "Continuing — the agent may need to be created manually in Agent Builder UI."
    AGENT_ID="security-analyst"
else
    print_info "Agent ID: ${AGENT_ID}"
fi
echo ""

################################################################################
# STEP 2: Create the reports index with mappings
################################################################################

print_step "[2/4] Creating reports index..."

REPORTS_INDEX="siem-demo-reports"

# Check if index exists
INDEX_EXISTS=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" \
    "${ES_URL}/${REPORTS_INDEX}" 2>/dev/null)

if [[ "$INDEX_EXISTS" == "200" ]]; then
    print_info "Index '${REPORTS_INDEX}' already exists."
else
    print_info "Creating index '${REPORTS_INDEX}'..."
    curl -sk -u "${AUTH}" \
        -X PUT \
        -H "Content-Type: application/json" \
        "${ES_URL}/${REPORTS_INDEX}" \
        -d '{
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "report_type": { "type": "keyword" },
                    "alert_id": { "type": "keyword" },
                    "alert_rule": { "type": "keyword" },
                    "source_host": { "type": "keyword" },
                    "source_agent_id": { "type": "keyword" },
                    "vulnerability_analysis": { "type": "text" },
                    "osquery_sql": { "type": "text" },
                    "fleet_results": { "type": "object", "enabled": false },
                    "report": { "type": "text" },
                    "execution_id": { "type": "keyword" }
                }
            }
        }' > /dev/null 2>&1

    # Verify
    INDEX_CHECK=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" \
        "${ES_URL}/${REPORTS_INDEX}" 2>/dev/null)
    if [[ "$INDEX_CHECK" == "200" ]]; then
        print_info "Index '${REPORTS_INDEX}' created."
    else
        print_error "Failed to create index '${REPORTS_INDEX}'."
    fi
fi
echo ""

################################################################################
# STEP 3: Look up the agent policy ID
################################################################################

print_step "[3/4] Looking up Fleet agent policy..."

POLICY_NAME="SIEM Demo - Endpoint Security"
POLICY_ID=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/fleet/agent_policies" 2>/dev/null \
    | jq -r ".items[]? | select(.name == \"${POLICY_NAME}\") | .id" 2>/dev/null || echo "")

if [[ -n "$POLICY_ID" ]]; then
    print_info "Found agent policy '${POLICY_NAME}' (ID: ${POLICY_ID})"
else
    print_warn "Agent policy '${POLICY_NAME}' not found."
    print_warn "Run deploy-elastic-agent.sh first, or set agent_policy_id manually in the workflow."
    POLICY_ID="REPLACE_ME"
fi
echo ""

################################################################################
# STEP 4: Import the workflow
################################################################################

print_step "[4/4] Importing workflow..."

if [[ ! -f "$WORKFLOW_DEF" ]]; then
    print_error "Workflow definition not found: ${WORKFLOW_DEF}"
    exit 1
fi

# Read the YAML and substitute the actual agent_id and policy_id
WORKFLOW_YAML=$(cat "$WORKFLOW_DEF" \
    | sed "s/agent_id: \"security-analyst\"/agent_id: \"${AGENT_ID}\"/" \
    | sed "s/agent_policy_id: \"REPLACE_ME\"/agent_policy_id: \"${POLICY_ID}\"/")

# Import via API — the YAML is sent as a JSON-escaped string
WORKFLOW_RESPONSE=$(echo "$WORKFLOW_YAML" | jq -Rs '{yaml: .}' | \
    curl -sk -u "${AUTH}" \
        -X POST \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/workflows" \
        -d @- 2>/dev/null)

WORKFLOW_ID=$(echo "$WORKFLOW_RESPONSE" | jq -r '.id // .data.id // empty' 2>/dev/null || echo "")

if [[ -n "$WORKFLOW_ID" ]]; then
    print_info "Workflow imported (ID: ${WORKFLOW_ID})"
else
    print_warn "Could not parse workflow ID from response. Response:"
    echo "$WORKFLOW_RESPONSE" | jq . 2>/dev/null || echo "$WORKFLOW_RESPONSE"
    print_warn "The workflow may need to be imported manually via Kibana UI."
fi
echo ""

################################################################################
# SUMMARY
################################################################################

echo "=========================================="
echo "Deployment Summary"
echo "=========================================="
echo ""
print_info "Agent Builder agent:  ${AGENT_NAME} (${AGENT_ID})"
print_info "Reports index:        ${REPORTS_INDEX}"
print_info "Fleet policy:         ${POLICY_ID}"
print_info "Workflow:             Defend Alert Triage (${WORKFLOW_ID:-manual import needed})"
echo ""
print_info "Kibana URLs:"
echo "  Agent Builder:  ${KIBANA_URL}/app/agent_builder"
echo "  Workflows:      ${KIBANA_URL}/app/management/insightsAndAlerting/workflows"
echo "  Fleet:          ${KIBANA_URL}/app/fleet/policies/${POLICY_ID}"
echo ""

if [[ "$POLICY_ID" == "REPLACE_ME" ]]; then
    print_warn "REMINDER: Update agent_policy_id in the workflow after running deploy-elastic-agent.sh."
fi

echo ""
print_info "Done."
