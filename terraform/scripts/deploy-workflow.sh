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
WORKFLOWS_DIR="${TERRAFORM_DIR}/workflows"

ALERT_ANALYZER_DEF="${WORKFLOWS_DIR}/agents/alert-analyzer.json"
OSQUERY_GENERATOR_DEF="${WORKFLOWS_DIR}/agents/osquery-generator.json"
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
# STEP 1: Remove old workflows and agents
################################################################################

print_step "[1/6] Removing old workflows and agents..."

WORKFLOW_NAME="Defend Alert Triage"
AGENT_IDS=("alert-analyzer" "osquery-generator" "security-analyst")

# Delete existing workflow by known ID (GET to check, DELETE if found)
# We can't list workflows, so try to delete by the name embedded in YAML
# by fetching each known workflow ID. Instead, we track the last deployed ID.
print_info "Checking for old workflows..."
# The workflow API doesn't support list, so we rely on the deploy creating
# a new one each time. Old workflows must be cleaned up by ID if known.

# Delete existing agents
for aid in "${AGENT_IDS[@]}"; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/agent_builder/agents/${aid}" 2>/dev/null)
    if [[ "$HTTP_CODE" == "200" ]]; then
        print_info "Deleting agent '${aid}'..."
        curl -sk -u "${AUTH}" \
            -X DELETE \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            "${KIBANA_URL}/api/agent_builder/agents/${aid}" > /dev/null 2>&1
    fi
done
print_info "Cleanup complete."
echo ""

################################################################################
# STEP 2: Create Agent Builder agents
################################################################################

print_step "[2/6] Creating Agent Builder agents..."

create_agent() {
    local def_file="$1"
    local agent_name
    agent_name=$(jq -r '.id' "$def_file")

    if [[ ! -f "$def_file" ]]; then
        print_error "Agent definition not found: ${def_file}"
        return 1
    fi

    print_info "Creating agent '${agent_name}'..."
    local response
    response=$(curl -sk -u "${AUTH}" \
        -X POST \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/agent_builder/agents" \
        -d @"$def_file" 2>/dev/null)
    local agent_id
    agent_id=$(echo "$response" | jq -r '.id // empty' 2>/dev/null || echo "")

    if [[ -n "$agent_id" ]]; then
        print_info "  Created: ${agent_id}"
    else
        print_warn "  Failed to create '${agent_name}'. Response:"
        echo "$response" | jq . 2>/dev/null || echo "$response"
    fi
}

create_agent "$ALERT_ANALYZER_DEF"
create_agent "$OSQUERY_GENERATOR_DEF"
echo ""

################################################################################
# STEP 2: Create the reports index with mappings
################################################################################

print_step "[3/6] Creating reports index..."

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
                    "fleet_columns": { "type": "object", "enabled": false },
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
# STEP 3: Look up inference connector ID
################################################################################

print_step "[4/6] Looking up inference connector..."

# Find an inference connector (type: inference.completion_stream or .inference)
CONNECTOR_ID=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
    | jq -r '[.[] | select(.connector_type_id == ".inference" or .connector_type_id == "inference.completion_stream")] | first | .id // empty' 2>/dev/null || echo "")

if [[ -n "$CONNECTOR_ID" ]]; then
    CONNECTOR_NAME=$(curl -sk -u "${AUTH}" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
        | jq -r ".[] | select(.id == \"${CONNECTOR_ID}\") | .name" 2>/dev/null || echo "unknown")
    print_info "Found inference connector '${CONNECTOR_NAME}' (ID: ${CONNECTOR_ID})"
else
    print_warn "No inference connector found. Available connector types:"
    curl -sk -u "${AUTH}" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
        | jq -r '.[].connector_type_id' 2>/dev/null | sort -u | head -20
    print_warn "Create an inference connector in Kibana, or set connector_id manually in the workflow."
    CONNECTOR_ID="REPLACE_ME"
fi
echo ""

################################################################################
# STEP 4: Look up the agent policy ID
################################################################################

print_step "[5/6] Looking up Fleet agent policy..."

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

print_step "[6/6] Importing workflow..."

if [[ ! -f "$WORKFLOW_DEF" ]]; then
    print_error "Workflow definition not found: ${WORKFLOW_DEF}"
    exit 1
fi

# Read the YAML and substitute connector_id and policy_id
# Agent IDs (alert-analyzer, osquery-generator) are already correct in the YAML
WORKFLOW_YAML=$(cat "$WORKFLOW_DEF" \
    | sed "s/connector_id: \"REPLACE_ME\"/connector_id: \"${CONNECTOR_ID}\"/" \
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
print_info "Alert Analyzer agent: alert-analyzer"
print_info "Osquery Generator:    osquery-generator"
print_info "Inference connector:  ${CONNECTOR_ID}"
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
