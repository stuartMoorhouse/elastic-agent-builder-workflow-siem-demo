#!/bin/bash

################################################################################
# Teardown script — deletes all workflows and cases from Kibana
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/teardown-workflow-and-cases.sh
#   ./terraform/scripts/teardown-workflow-and-cases.sh workflow-<uuid>  # extra IDs
################################################################################

set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-common.sh"
trap 'cleanup_curl_auth' EXIT

STATE_DIR="${PROJECT_DIR}/state"
WORKFLOW_ID_FILE="${STATE_DIR}/workflow-id"

cd "$TERRAFORM_DIR"

KIBANA_URL=$(terraform output -raw kibana_endpoint)
ES_USER=$(terraform output -raw elasticsearch_username)
ES_PASS=$(terraform output -raw elasticsearch_password)
setup_curl_auth "$ES_USER" "$ES_PASS"

echo "=========================================="
echo "Teardown — Workflows and Cases"
echo "=========================================="
echo ""

# --------------------------------------------------------------------------
# Delete workflows
# --------------------------------------------------------------------------
FOUND=0

# Read last deployed workflow ID from state file
if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    SAVED_ID=$(cat "$WORKFLOW_ID_FILE")
    if [[ -n "$SAVED_ID" ]]; then
        print_info "Deleting workflow ${SAVED_ID} (from state file)..."
        HTTP_CODE=$(curl -s -K "$CURL_AUTH_CONF" \
            -X DELETE \
            -H "kbn-xsrf: true" \
            -H "x-elastic-internal-origin: Kibana" \
            -o /dev/null -w "%{http_code}" \
            "${KIBANA_URL}/api/workflows/${SAVED_ID}" 2>/dev/null)
        if [[ "$HTTP_CODE" == "200" ]]; then
            FOUND=$((FOUND + 1))
        else
            print_warn "Workflow ${SAVED_ID} not found (HTTP ${HTTP_CODE}), may already be deleted."
        fi
        rm -f "$WORKFLOW_ID_FILE"
    fi
else
    print_warn "No state/workflow-id file found. Pass workflow IDs as arguments if needed."
fi

# Delete any extra workflows passed as arguments
for wid in "$@"; do
    print_info "Deleting workflow ${wid}..."
    HTTP_CODE=$(curl -s -K "$CURL_AUTH_CONF" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -o /dev/null -w "%{http_code}" \
        "${KIBANA_URL}/api/workflows/${wid}" 2>/dev/null)
    if [[ "$HTTP_CODE" == "200" ]]; then
        FOUND=$((FOUND + 1))
    else
        print_warn "Workflow ${wid} not found (HTTP ${HTTP_CODE})."
    fi
done

print_info "Deleted ${FOUND} workflow(s)."
echo ""

# --------------------------------------------------------------------------
# Delete all cases
# --------------------------------------------------------------------------
print_info "Searching for cases..."

CASE_IDS=$(curl -s -K "$CURL_AUTH_CONF" \
    -H "kbn-xsrf: true" \
    -H "x-elastic-internal-origin: Kibana" \
    "${KIBANA_URL}/api/cases/_find?perPage=100" 2>/dev/null \
    | jq -r '.cases[]?.id // empty' 2>/dev/null || echo "")

if [[ -z "$CASE_IDS" ]]; then
    print_info "No cases found."
else
    # URL-encode the ids array as a query parameter
    IDS_JSON=$(echo "$CASE_IDS" | jq -R . | jq -s -c .)
    IDS_ENCODED=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$IDS_JSON")

    COUNT=$(echo "$CASE_IDS" | wc -l | tr -d ' ')
    print_info "Deleting ${COUNT} case(s)..."

    HTTP_CODE=$(curl -s -K "$CURL_AUTH_CONF" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        -o /dev/null -w "%{http_code}" \
        "${KIBANA_URL}/api/cases?ids=${IDS_ENCODED}" 2>/dev/null)

    if [[ "$HTTP_CODE" == "204" ]]; then
        print_info "Deleted ${COUNT} case(s)."
    else
        print_error "Failed to delete cases (HTTP ${HTTP_CODE})."
    fi
fi

echo ""
print_info "Teardown complete."
