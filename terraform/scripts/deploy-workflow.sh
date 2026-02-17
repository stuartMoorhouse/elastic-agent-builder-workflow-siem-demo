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
REPORT_WRITER_DEF="${WORKFLOWS_DIR}/agents/report-writer.json"
REPORT_TEMPLATE="${WORKFLOWS_DIR}/templates/incident-report-template.md"
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

print_step "[1/8] Removing old workflows and agents..."

WORKFLOW_NAME="Defend Alert Triage"
AGENT_IDS=("alert-analyzer" "osquery-generator" "report-writer" "security-analyst")

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

print_step "[2/8] Creating Agent Builder agents..."

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

print_step "[3/8] Looking up inference connector..."

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
# STEP 4: Look up Fleet agent policy
################################################################################

print_step "[4/8] Looking up Fleet agent policy..."

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
# STEP 5: Import the workflow
################################################################################

print_step "[5/8] Importing workflow..."

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
# STEP 6: Install and enable detection rules
################################################################################

print_step "[6/8] Installing prebuilt detection rules..."

# Install/update prebuilt rules package
HTTP_CODE=$(curl -sk -u "${AUTH}" \
    -X PUT \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    -o /dev/null -w "%{http_code}" \
    "${KIBANA_URL}/api/detection_engine/rules/prepackaged" 2>/dev/null)

if [[ "$HTTP_CODE" == "200" ]]; then
    print_info "Prebuilt rules installed."
else
    print_warn "Prebuilt rules install returned HTTP ${HTTP_CODE} (may already be up to date)."
fi

# Enable prebuilt detection rules needed for the demo (with 10s interval for fast alerting)
# Use rule_id (Elastic's prebuilt rule definition ID) for reliable lookup
PREBUILT_RULES=(
    "c3f5e1d8-910e-43b4-8d44-d748e498ca86|Potential JAVA/JNDI Exploitation Attempt"
)

PREBUILT_RULE_IDS=()  # Collect saved-object IDs for workflow attachment later

for RULE_ENTRY in "${PREBUILT_RULES[@]}"; do
    PREBUILT_RULE_ID="${RULE_ENTRY%%|*}"
    RULE_NAME="${RULE_ENTRY##*|}"

    # Look up by rule_id (the prebuilt definition ID)
    RULE_RESULT=$(curl -sk -u "${AUTH}" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/detection_engine/rules?rule_id=${PREBUILT_RULE_ID}" 2>/dev/null)

    RULE_ID=$(echo "$RULE_RESULT" | jq -r '.id // empty' 2>/dev/null || echo "")

    if [[ -n "$RULE_ID" ]]; then
        curl -sk -u "${AUTH}" \
            -X PATCH \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            -H "Content-Type: application/json" \
            "${KIBANA_URL}/api/detection_engine/rules" \
            -d "{\"id\": \"${RULE_ID}\", \"enabled\": true, \"interval\": \"10s\"}" > /dev/null 2>&1
        print_info "Enabled rule: ${RULE_NAME} (${RULE_ID}) — interval: 10s"
        PREBUILT_RULE_IDS+=("$RULE_ID")
    else
        print_warn "Could not find rule: ${RULE_NAME} (rule_id: ${PREBUILT_RULE_ID})"
    fi
done
echo ""

################################################################################
# STEP 7: Create custom detection rule for Log4Shell exploit
################################################################################

print_step "[7/8] Creating custom detection rule..."

CUSTOM_RULE_NAME="Shell Spawned by Java Process"

# Check if rule already exists
EXISTING_RULE=$(curl -sk -u "${AUTH}" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/detection_engine/rules/_find?per_page=100&search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${CUSTOM_RULE_NAME}'))")&search_fields=name" 2>/dev/null)

EXISTING_RULE_ID=$(echo "$EXISTING_RULE" | jq -r ".data[] | select(.name == \"${CUSTOM_RULE_NAME}\") | .id" 2>/dev/null | head -1)

if [[ -n "$EXISTING_RULE_ID" ]]; then
    print_info "Custom rule '${CUSTOM_RULE_NAME}' already exists (${EXISTING_RULE_ID}), updating..."
    CUSTOM_RESPONSE=$(curl -sk -u "${AUTH}" \
        -X PATCH \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/detection_engine/rules" \
        -d "{
            \"id\": \"${EXISTING_RULE_ID}\",
            \"enabled\": true,
            \"interval\": \"10s\",
            \"from\": \"now-60m\"
        }" 2>/dev/null)
    print_info "Updated and enabled rule: ${CUSTOM_RULE_NAME}"
else
    print_info "Creating custom rule '${CUSTOM_RULE_NAME}'..."
    CUSTOM_RESPONSE=$(curl -sk -u "${AUTH}" \
        -X POST \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/detection_engine/rules" \
        -d '{
            "name": "Shell Spawned by Java Process",
            "description": "Detects a shell process (sh, bash, dash, etc.) spawned as a child of a Java process. This is a strong indicator of exploitation via Log4Shell (CVE-2021-44228) or similar Java deserialization/JNDI injection attacks where the attacker achieves remote code execution through the JVM.",
            "type": "eql",
            "language": "eql",
            "query": "process where event.type == \"start\" and host.os.type == \"linux\" and process.parent.name == \"java\" and process.name in (\"sh\", \"bash\", \"dash\", \"ksh\", \"tcsh\", \"zsh\")",
            "index": ["logs-endpoint.events.process-*"],
            "severity": "high",
            "risk_score": 73,
            "enabled": true,
            "interval": "10s",
            "from": "now-60m",
            "tags": ["Log4Shell", "CVE-2021-44228", "Java Exploitation", "SIEM Demo"],
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0002",
                        "name": "Execution",
                        "reference": "https://attack.mitre.org/tactics/TA0002/"
                    },
                    "technique": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "reference": "https://attack.mitre.org/techniques/T1059/",
                            "subtechnique": [
                                {
                                    "id": "T1059.004",
                                    "name": "Unix Shell",
                                    "reference": "https://attack.mitre.org/techniques/T1059/004/"
                                }
                            ]
                        }
                    ]
                },
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": "TA0001",
                        "name": "Initial Access",
                        "reference": "https://attack.mitre.org/tactics/TA0001/"
                    },
                    "technique": [
                        {
                            "id": "T1190",
                            "name": "Exploit Public-Facing Application",
                            "reference": "https://attack.mitre.org/techniques/T1190/"
                        }
                    ]
                }
            ]
        }' 2>/dev/null)

    CUSTOM_RULE_ID=$(echo "$CUSTOM_RESPONSE" | jq -r '.id // empty' 2>/dev/null || echo "")
    if [[ -n "$CUSTOM_RULE_ID" ]]; then
        print_info "Created rule: ${CUSTOM_RULE_NAME} (${CUSTOM_RULE_ID}) — interval: 10s, lookback: 60m"
    else
        print_warn "Failed to create custom rule. Response:"
        echo "$CUSTOM_RESPONSE" | jq . 2>/dev/null || echo "$CUSTOM_RESPONSE"
    fi
fi
echo ""

################################################################################
# STEP 8: Attach workflow as action on detection rules
################################################################################

print_step "[8/8] Attaching workflow to detection rules..."

if [[ -n "$WORKFLOW_ID" && "$WORKFLOW_ID" != "null" ]]; then
    # Collect all rule IDs to attach the workflow to
    ATTACH_RULE_IDS=()

    # Prebuilt rules (collected during step 6)
    ATTACH_RULE_IDS+=("${PREBUILT_RULE_IDS[@]}")

    # Custom rule (from step 7)
    if [[ -n "$EXISTING_RULE_ID" ]]; then
        ATTACH_RULE_IDS+=("$EXISTING_RULE_ID")
    elif [[ -n "$CUSTOM_RULE_ID" ]]; then
        ATTACH_RULE_IDS+=("$CUSTOM_RULE_ID")
    fi

    # Workflow actions use the system connector "system-connector-.workflows"
    # with subAction "run" and the workflow ID in subActionParams
    for RULE_ID in "${ATTACH_RULE_IDS[@]}"; do
        # Get the rule name for logging
        RULE_INFO=$(curl -sk -u "${AUTH}" \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            "${KIBANA_URL}/api/detection_engine/rules?id=${RULE_ID}" 2>/dev/null)
        RULE_DISPLAY_NAME=$(echo "$RULE_INFO" | jq -r '.name // "unknown"' 2>/dev/null)

        # PATCH the rule to add the workflow action
        PATCH_RESPONSE=$(curl -sk -u "${AUTH}" \
            -X PATCH \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            -H "Content-Type: application/json" \
            "${KIBANA_URL}/api/detection_engine/rules" \
            -d "$(cat <<ACTIONJSON
{
    "id": "${RULE_ID}",
    "actions": [
        {
            "id": "system-connector-.workflows",
            "action_type_id": ".workflows",
            "params": {
                "subAction": "run",
                "subActionParams": {
                    "workflowId": "${WORKFLOW_ID}",
                    "summaryMode": false
                }
            }
        }
    ]
}
ACTIONJSON
)" 2>/dev/null)

        PATCHED_ID=$(echo "$PATCH_RESPONSE" | jq -r '.id // empty' 2>/dev/null || echo "")
        if [[ -n "$PATCHED_ID" ]]; then
            print_info "Attached workflow to rule: ${RULE_DISPLAY_NAME} (${RULE_ID})"
        else
            print_warn "Could not attach workflow to rule '${RULE_DISPLAY_NAME}'. Response:"
            echo "$PATCH_RESPONSE" | jq . 2>/dev/null || echo "$PATCH_RESPONSE"
        fi
    done
else
    print_warn "No workflow ID available — skipping rule attachment."
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
print_info "Detection rules:      Shell Spawned by Java Process + Potential JAVA/JNDI Exploitation Attempt"
print_info "Workflow trigger:     Attached to detection rules (fires on every alert)"
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
