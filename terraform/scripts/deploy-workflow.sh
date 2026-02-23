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

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-common.sh"
trap 'cleanup_curl_auth' EXIT

WORKFLOWS_DIR="${TERRAFORM_DIR}/workflows"

ALERT_ANALYZER_DEF="${WORKFLOWS_DIR}/agents/alert-analyzer.json"
OSQUERY_GENERATOR_DEF="${WORKFLOWS_DIR}/agents/osquery-generator.json"
REPORT_WRITER_DEF="${WORKFLOWS_DIR}/agents/report-writer.json"
REPORT_TEMPLATE="${WORKFLOWS_DIR}/templates/incident-report-template.md"
WORKFLOW_DEF="${WORKFLOWS_DIR}/alert-triage.yaml"

################################################################################
# READ TERRAFORM OUTPUTS
################################################################################

echo "=========================================="
echo "Agent Builder + Workflow Deployment"
echo "=========================================="
echo ""

print_step "Reading Terraform outputs..."

read_terraform_outputs

print_info "Kibana URL: ${KIBANA_URL}"
print_info "ES URL:     ${ES_URL}"
echo ""

# Verify connectivity
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -K "$CURL_AUTH_CONF" "${KIBANA_URL}/api/status" 2>/dev/null)
if [[ "$HTTP_CODE" != "200" ]]; then
    print_error "Cannot reach Kibana (HTTP ${HTTP_CODE}). Is the deployment running?"
    exit 1
fi
print_info "Kibana is reachable."

################################################################################
# STEP 1: Remove old workflows and agents
################################################################################

print_step "[1/7] Removing old workflows and agents..."

WORKFLOW_NAME="Defend Alert Triage"
AGENT_IDS=("alert-analyzer" "osquery-generator" "report-writer" "security-analyst")

# Delete old workflow tracked in state/workflow-id (API doesn't support list)
WORKFLOW_ID_FILE="${PROJECT_DIR}/state/workflow-id"
if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    OLD_WORKFLOW_ID=$(cat "$WORKFLOW_ID_FILE" | tr -d '[:space:]')
    if [[ -n "$OLD_WORKFLOW_ID" ]]; then
        print_info "Deleting old workflow ${OLD_WORKFLOW_ID}..."
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -K "$CURL_AUTH_CONF" \
            -X DELETE \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            "${KIBANA_URL}/api/workflows/${OLD_WORKFLOW_ID}" 2>/dev/null)
        if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]; then
            print_info "  Deleted."
        else
            print_warn "  Could not delete (HTTP ${HTTP_CODE}) — may already be gone."
        fi
    fi
    rm -f "$WORKFLOW_ID_FILE"
fi

# Delete existing agents
for aid in "${AGENT_IDS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -K "$CURL_AUTH_CONF" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/agent_builder/agents/${aid}" 2>/dev/null)
    if [[ "$HTTP_CODE" == "200" ]]; then
        print_info "Deleting agent '${aid}'..."
        curl -s -K "$CURL_AUTH_CONF" \
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

print_step "[2/7] Creating Agent Builder agents..."

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
    response=$(curl -s -K "$CURL_AUTH_CONF" \
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

# Build report-writer instructions by inlining the Markdown template
if [[ -f "$REPORT_TEMPLATE" ]]; then
    REPORT_PREAMBLE="You are a senior security analyst writing incident reports for a SOC team.\n\nYou will receive: source alert data (JSON), a vulnerability analysis, an osquery SQL query, and fleet scan results (columns + values). Use ALL of this data to produce a report.\n\nUse this exact template structure. Fill every field from the data provided. Use Markdown formatting with headings, bold labels, and bulleted lists. Do NOT use Markdown tables — use bullet lists instead.\n\n---\n\n"
    REPORT_GUIDELINES="\n\n---\n\nGuidelines:\n- Fill EVERY field from the data provided. Do not leave placeholders.\n- Extract the Report ID date, timestamp, and all alert fields from the source alert JSON.\n- For the process tree, use the process and process.parent fields from the alert data.\n- For IOCs, extract IPs, file paths, and suspicious processes from the alert data.\n- For fleet results, list each host with bullet points — do NOT use tables.\n- Do NOT invent data not present in the inputs. If a field cannot be determined, write 'Not available'.\n- Be concise and actionable throughout."
    TEMPLATE_CONTENT=$(cat "$REPORT_TEMPLATE")
    FULL_INSTRUCTIONS="${REPORT_PREAMBLE}${TEMPLATE_CONTENT}${REPORT_GUIDELINES}"

    # Build the JSON with the inlined template
    REPORT_WRITER_JSON=$(cat "$REPORT_WRITER_DEF" | \
        jq --arg instructions "$FULL_INSTRUCTIONS" '.configuration.instructions = $instructions')

    # Write to temp file for create_agent
    REPORT_WRITER_TMP=$(mktemp)
    echo "$REPORT_WRITER_JSON" > "$REPORT_WRITER_TMP"
    create_agent "$REPORT_WRITER_TMP"
    rm -f "$REPORT_WRITER_TMP"
else
    print_warn "Report template not found at ${REPORT_TEMPLATE}, using raw JSON"
    create_agent "$REPORT_WRITER_DEF"
fi
echo ""

################################################################################
# STEP 3: Look up inference connector
################################################################################

print_step "[3/7] Looking up inference connector..."

# Find an inference connector (type: inference.completion_stream or .inference)
CONNECTOR_ID=$(curl -s -K "$CURL_AUTH_CONF" \
    -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
    | jq -r '[.[] | select(.connector_type_id == ".inference" or .connector_type_id == "inference.completion_stream")] | first | .id // empty' 2>/dev/null || echo "")

if [[ -n "$CONNECTOR_ID" ]]; then
    CONNECTOR_NAME=$(curl -s -K "$CURL_AUTH_CONF" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
        | jq -r ".[] | select(.id == \"${CONNECTOR_ID}\") | .name" 2>/dev/null || echo "unknown")
    print_info "Found inference connector '${CONNECTOR_NAME}' (ID: ${CONNECTOR_ID})"
else
    print_warn "No inference connector found. Available connector types:"
    curl -s -K "$CURL_AUTH_CONF" \
        -H "kbn-xsrf: true" \
        "${KIBANA_URL}/api/actions/connectors" 2>/dev/null \
        | jq -r '.[].connector_type_id' 2>/dev/null | sort -u | head -20
    print_warn "Create an inference connector in Kibana, or set connector_id manually in the workflow."
    CONNECTOR_ID="REPLACE_ME"
fi
echo ""

################################################################################
# STEP 4: Look up Fleet agent policy
################################################################################

print_step "[4/7] Looking up Fleet agent policy..."

POLICY_NAME="SIEM Demo - Endpoint Security"
POLICY_ID=$(curl -s -K "$CURL_AUTH_CONF" \
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
# STEP 5: Import the workflow
################################################################################

print_step "[5/7] Importing workflow..."

if [[ ! -f "$WORKFLOW_DEF" ]]; then
    print_error "Workflow definition not found: ${WORKFLOW_DEF}"
    exit 1
fi

# Read the YAML and substitute connector_id and agent_policy_id with values
# discovered from the Kibana API (steps 3-4 above)
WORKFLOW_YAML=$(cat "$WORKFLOW_DEF" \
    | sed "s|connector_id: \".*\"|connector_id: \"${CONNECTOR_ID}\"|" \
    | sed "s|agent_policy_id: \".*\"|agent_policy_id: \"${POLICY_ID}\"|")

# Import via API — the YAML is sent as a JSON-escaped string
WORKFLOW_RESPONSE=$(echo "$WORKFLOW_YAML" | jq -Rs '{yaml: .}' | \
    curl -s -K "$CURL_AUTH_CONF" \
        -X POST \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/workflows" \
        -d @- 2>/dev/null)

WORKFLOW_ID=$(echo "$WORKFLOW_RESPONSE" | jq -r '.id // .data.id // empty' 2>/dev/null || echo "")

if [[ -n "$WORKFLOW_ID" ]]; then
    print_info "Workflow imported (ID: ${WORKFLOW_ID})"
    # Save workflow ID for teardown script
    STATE_DIR="${PROJECT_DIR}/state"
    mkdir -p "$STATE_DIR"
    echo "$WORKFLOW_ID" > "${STATE_DIR}/workflow-id"
else
    print_warn "Could not parse workflow ID from response. Response:"
    echo "$WORKFLOW_RESPONSE" | jq . 2>/dev/null || echo "$WORKFLOW_RESPONSE"
    print_warn "The workflow may need to be imported manually via Kibana UI."
fi
echo ""

################################################################################
# STEP 6: Create detection rule with workflow action
#
# Uses a stable rule_id so redeploys always update the same rule rather than
# creating duplicates. Deletes any stale copies first.
################################################################################

print_step "[6/7] Creating detection rule..."

CUSTOM_RULE_NAME="Shell Spawned by Java Process"
STABLE_RULE_ID="siem-demo-shell-spawned-by-java"

# Delete ALL existing rules with this name (cleans up duplicates from prior deploys)
EXISTING_IDS=$(curl -s -K "$CURL_AUTH_CONF" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/detection_engine/rules/_find?per_page=100" 2>/dev/null \
    | jq -r ".data[] | select(.name == \"${CUSTOM_RULE_NAME}\") | .id" 2>/dev/null)

for OLD_ID in $EXISTING_IDS; do
    print_info "Deleting old rule ${OLD_ID}..."
    curl -s -K "$CURL_AUTH_CONF" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/detection_engine/rules?id=${OLD_ID}" > /dev/null 2>&1
done

# Also delete by our stable rule_id in case name was changed
curl -s -K "$CURL_AUTH_CONF" \
    -X DELETE \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/detection_engine/rules?rule_id=${STABLE_RULE_ID}" > /dev/null 2>&1

# Build the workflow action JSON (empty if no workflow)
if [[ -n "$WORKFLOW_ID" && "$WORKFLOW_ID" != "null" ]]; then
    ACTIONS_JSON="[{
        \"id\": \"system-connector-.workflows\",
        \"action_type_id\": \".workflows\",
        \"params\": {
            \"subAction\": \"run\",
            \"subActionParams\": {
                \"workflowId\": \"${WORKFLOW_ID}\",
                \"summaryMode\": false
            }
        }
    }]"
else
    ACTIONS_JSON="[]"
fi

# Create rule with stable rule_id and workflow action attached in one shot
print_info "Creating rule '${CUSTOM_RULE_NAME}' with workflow action..."
CUSTOM_RESPONSE=$(curl -s -K "$CURL_AUTH_CONF" \
    -X POST \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    -H "Content-Type: application/json" \
    "${KIBANA_URL}/api/detection_engine/rules" \
    -d "{
        \"rule_id\": \"${STABLE_RULE_ID}\",
        \"name\": \"Shell Spawned by Java Process\",
        \"description\": \"Detects a shell process spawned by Java — indicates Log4Shell (CVE-2021-44228) or similar JNDI injection exploitation.\",
        \"type\": \"eql\",
        \"language\": \"eql\",
        \"query\": \"process where event.type == \\\"start\\\" and host.os.type == \\\"linux\\\" and process.parent.name == \\\"java\\\" and process.name in (\\\"sh\\\", \\\"bash\\\", \\\"dash\\\", \\\"ksh\\\", \\\"tcsh\\\", \\\"zsh\\\")\",
        \"index\": [\"logs-endpoint.events.process-*\"],
        \"severity\": \"high\",
        \"risk_score\": 73,
        \"enabled\": true,
        \"interval\": \"10s\",
        \"from\": \"now-2m\",
        \"tags\": [\"Log4Shell\", \"CVE-2021-44228\", \"SIEM Demo\"],
        \"alert_suppression\": {
            \"group_by\": [\"host.name\"],
            \"duration\": {\"value\": 1, \"unit\": \"h\"},
            \"missing_fields_strategy\": \"suppress\"
        },
        \"actions\": ${ACTIONS_JSON},
        \"threat\": [
            {
                \"framework\": \"MITRE ATT&CK\",
                \"tactic\": {
                    \"id\": \"TA0002\",
                    \"name\": \"Execution\",
                    \"reference\": \"https://attack.mitre.org/tactics/TA0002/\"
                },
                \"technique\": [{
                    \"id\": \"T1059\",
                    \"name\": \"Command and Scripting Interpreter\",
                    \"reference\": \"https://attack.mitre.org/techniques/T1059/\",
                    \"subtechnique\": [{
                        \"id\": \"T1059.004\",
                        \"name\": \"Unix Shell\",
                        \"reference\": \"https://attack.mitre.org/techniques/T1059/004/\"
                    }]
                }]
            },
            {
                \"framework\": \"MITRE ATT&CK\",
                \"tactic\": {
                    \"id\": \"TA0001\",
                    \"name\": \"Initial Access\",
                    \"reference\": \"https://attack.mitre.org/tactics/TA0001/\"
                },
                \"technique\": [{
                    \"id\": \"T1190\",
                    \"name\": \"Exploit Public-Facing Application\",
                    \"reference\": \"https://attack.mitre.org/techniques/T1190/\"
                }]
            }
        ]
    }" 2>/dev/null)

CUSTOM_RULE_ID=$(echo "$CUSTOM_RESPONSE" | jq -r '.id // empty' 2>/dev/null || echo "")
if [[ -n "$CUSTOM_RULE_ID" ]]; then
    print_info "Created rule: ${CUSTOM_RULE_NAME} (${CUSTOM_RULE_ID}) — interval: 10s, lookback: 2m"
    if [[ -n "$WORKFLOW_ID" && "$WORKFLOW_ID" != "null" ]]; then
        print_info "Workflow ${WORKFLOW_ID} attached to rule"
    fi
else
    print_warn "Failed to create rule. Response:"
    echo "$CUSTOM_RESPONSE" | jq . 2>/dev/null || echo "$CUSTOM_RESPONSE"
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
print_info "Report Writer:        report-writer"
print_info "Inference connector:  ${CONNECTOR_ID}"
print_info "Fleet policy:         ${POLICY_ID}"
print_info "Workflow:             Defend Alert Triage (${WORKFLOW_ID:-manual import needed})"
print_info "Detection rule:       Shell Spawned by Java Process (rule_id: ${STABLE_RULE_ID})"
print_info "Workflow trigger:     Attached to detection rule (fires on every alert)"
echo ""
print_info "Kibana URLs:"
echo "  Agent Builder:  ${KIBANA_URL}/app/agent_builder"
echo "  Workflows:      ${KIBANA_URL}/app/management/insightsAndAlerting/workflows"
echo "  Fleet:          ${KIBANA_URL}/app/fleet/policies/${POLICY_ID}"
echo ""

print_info "Done."
