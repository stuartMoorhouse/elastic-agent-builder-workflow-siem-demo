#!/bin/bash

################################################################################
# Teardown script — deletes all workflows and cases from Kibana
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/teardown-workflow-and-cases.sh
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"

cd "$TERRAFORM_DIR"

KIBANA_URL=$(terraform output -raw kibana_endpoint)
ES_USER=$(terraform output -raw elasticsearch_username)
ES_PASS=$(terraform output -raw elasticsearch_password)
AUTH="${ES_USER}:${ES_PASS}"

echo "=========================================="
echo "Teardown — Workflows and Cases"
echo "=========================================="
echo ""

# --------------------------------------------------------------------------
# Delete all workflows
# --------------------------------------------------------------------------
print_info "Searching for workflows..."

# Fetch workflow IDs from the .kibana alerting cases index
ES_URL=$(terraform output -raw elasticsearch_endpoint)
WORKFLOW_IDS=$(curl -sk -u "${AUTH}" \
    "${ES_URL}/.kibana_alerting_cases*/_search" \
    -H "Content-Type: application/json" \
    -d '{"query":{"term":{"type":"workflow"}},"size":100,"_source":false}' 2>/dev/null \
    | jq -r '.hits.hits[]._id // empty' 2>/dev/null \
    | sed 's/^workflow://' || echo "")

if [[ -z "$WORKFLOW_IDS" ]]; then
    # Fallback: try fetching known workflow names via saved objects
    WORKFLOW_IDS=$(curl -sk -u "${AUTH}" \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/saved_objects/_find?type=workflow&per_page=100" 2>/dev/null \
        | jq -r '.saved_objects[]?.id // empty' 2>/dev/null || echo "")
fi

FOUND=0
for wid in $WORKFLOW_IDS; do
    print_info "Deleting workflow ${wid}..."
    curl -sk -u "${AUTH}" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/workflows/${wid}" > /dev/null 2>&1
    FOUND=$((FOUND + 1))
done

if [[ "$FOUND" -eq 0 ]]; then
    print_warn "No workflows found via index search. Listing any known IDs from recent deploys..."
    print_warn "If workflows remain, delete them manually or pass IDs as arguments:"
    print_warn "  $0 workflow-<uuid>"
fi

# Delete workflows passed as arguments
for wid in "$@"; do
    print_info "Deleting workflow ${wid}..."
    curl -sk -u "${AUTH}" \
        -X DELETE \
        -H "kbn-xsrf: true" \
        -H "x-elastic-internal-origin: Kibana" \
        "${KIBANA_URL}/api/workflows/${wid}" > /dev/null 2>&1
    FOUND=$((FOUND + 1))
done

print_info "Deleted ${FOUND} workflow(s)."
echo ""

# --------------------------------------------------------------------------
# Delete all cases
# --------------------------------------------------------------------------
print_info "Searching for cases..."

CASE_IDS=$(curl -sk -u "${AUTH}" \
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

    HTTP_CODE=$(curl -sk -u "${AUTH}" \
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
