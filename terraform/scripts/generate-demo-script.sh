#!/bin/bash

################################################################################
# Generate Demo Script
#
# Produces a "demo-script.md" file with all the commands the presenter needs
# to run the demo, pre-filled with actual IPs from the terraform deployment.
#
# Called automatically by terraform apply as the final provisioning step.
################################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"

cd "$TERRAFORM_DIR"

# Read terraform outputs
KIBANA_URL=$(terraform output -raw kibana_endpoint)
ES_URL=$(terraform output -raw elasticsearch_endpoint)
ES_USER=$(terraform output -raw elasticsearch_username)
ELASTIC_VERSION=$(terraform output -raw deployment_version)
SSH_KEY="${PROJECT_DIR}/state/ssh-key.pem"

PROJECT_PREFIX=$(terraform output -raw project_prefix)
REPORTS_INDEX="${PROJECT_PREFIX}-reports"

REDTEAM_PUB=$(terraform output -raw redteam_public_ip)
REDTEAM_PRIV=$(terraform output -raw redteam_private_ip)

HOST_PUBLIC_JSON=$(terraform output -json host_public_ips)
HOST_PRIVATE_JSON=$(terraform output -json host_private_ips)

SOLR_KB_PUB=$(echo "$HOST_PUBLIC_JSON" | jq -r '.["solr-kb"]')
SOLR_KB_PRIV=$(echo "$HOST_PRIVATE_JSON" | jq -r '.["solr-kb"]')
SOLR_SUPPORT_PUB=$(echo "$HOST_PUBLIC_JSON" | jq -r '.["solr-support"]')
SOLR_SUPPORT_PRIV=$(echo "$HOST_PRIVATE_JSON" | jq -r '.["solr-support"]')
SOLR_CATALOG_PUB=$(echo "$HOST_PUBLIC_JSON" | jq -r '.["solr-catalog"]')
SOLR_CATALOG_PRIV=$(echo "$HOST_PRIVATE_JSON" | jq -r '.["solr-catalog"]')

OUTPUT="${PROJECT_DIR}/demo-script.md"

cat > "$OUTPUT" << EOF
# Operation Bad Memories - Demo Script

## Environment

| Host | Role | Public IP | Private IP |
|------|------|-----------|------------|
| attacker | Red team (Metasploit, nmap, nuclei) | ${REDTEAM_PUB} | ${REDTEAM_PRIV} |
| solr-kb | Knowledge Base - Solr 8.11.0/JDK 8u181 (VULNERABLE) | ${SOLR_KB_PUB} | ${SOLR_KB_PRIV} |
| solr-support | Support Portal - Solr 8.11.0/JDK 8u181 (VULNERABLE) | ${SOLR_SUPPORT_PUB} | ${SOLR_SUPPORT_PRIV} |
| solr-catalog | Product Catalog - Solr 8.11.1/JDK 8u352 (PATCHED) | ${SOLR_CATALOG_PUB} | ${SOLR_CATALOG_PRIV} |

Subnet: 10.0.1.0/24
Elastic Stack: ${ELASTIC_VERSION}
Kibana: ${KIBANA_URL}

---

## Pre-demo: Verify the environment

SSH into the attacker VM:

\`\`\`bash
ssh -i ${SSH_KEY} ubuntu@${REDTEAM_PUB}
\`\`\`

Confirm tools are installed:

\`\`\`bash
nmap --version && msfconsole --version && nuclei --version
\`\`\`

Open Kibana Security in a browser: ${KIBANA_URL}/app/security

Confirm 3 agents are healthy: ${KIBANA_URL}/app/fleet/agents

---

## Phase 1+2 - Attack (from attacker VM)

Run the attack script. It handles everything: nmap scan, Solr version fingerprinting,
Log4Shell identification, Metasploit exploitation, and post-exploitation.

All commands and their output are displayed in the terminal as they execute.

\`\`\`bash
./scripts/host-scan.sh -s 10.0.1.0/24 -a ${REDTEAM_PRIV}
\`\`\`

What it does:

1. **Phase 1a** - nmap scans the subnet, discovers 3 hosts with port 8983 open
2. **Phase 1b** - Queries each Solr admin API, prints version + JDK, flags CVE-2021-44228
3. **Phase 1c** - Runs nuclei to confirm exploitability (if available)
4. **Phase 2** - Launches Metasploit \`log4shell_header_injection\`, gets reverse shell
5. **Phase 3** - Discovery: whoami, uname, processes, log4j JARs on disk
6. **Phase 4** - Privilege escalation: checks sudo access
7. **Phase 5** - Persistence: installs cron callback
8. **Phase 6** - Credential access: dumps /etc/shadow
9. **Phase 7** - Collection: archives sensitive files

To skip recon and target a specific host:

\`\`\`bash
./scripts/host-scan.sh -t ${SOLR_KB_PRIV} -a ${REDTEAM_PRIV}
\`\`\`

---

## Phase 3 - Observe (Kibana)

### Check Elastic Security alerts

Open: ${KIBANA_URL}/app/security/alerts

Defend alerts should appear for:
- Reverse shell execution
- /etc/shadow read
- Crontab modification
- Archive creation (loot.tar.gz)

### Check the workflow execution

Open: ${KIBANA_URL}/app/management/insightsAndAlerting/workflows

The Defend Alert Triage workflow triggers automatically on alerts:
1. Sends alert to AI agent for vulnerability analysis
2. Generates an osquery to detect Log4Shell fleet-wide
3. Tests the query on the source host
4. Runs it across all monitored hosts
5. Indexes an incident report to \`${REPORTS_INDEX}\`

### View the report

Get the Elasticsearch password (run from your laptop, not the attacker VM):

\`\`\`bash
cd ${TERRAFORM_DIR} && terraform output -raw elasticsearch_password
\`\`\`

Query the reports index (replace \`<PASSWORD>\`):

\`\`\`bash
curl -s -u "${ES_USER}:<PASSWORD>" \\
  "${ES_URL}/${REPORTS_INDEX}/_search?pretty&size=1&sort=@timestamp:desc"
\`\`\`

Or open Kibana Discover: ${KIBANA_URL}/app/discover (index pattern: \`${REPORTS_INDEX}\`)

### Run osquery manually (optional)

Open: ${KIBANA_URL}/app/osquery

Run a live query to find vulnerable Log4j JARs across all agents:

\`\`\`sql
SELECT f.path, f.filename,
  REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) AS log4j_version
FROM file f
WHERE (f.path LIKE '/opt/%/log4j-core-%.jar'
  OR f.path LIKE '/var/%/log4j-core-%.jar')
  AND REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) >= '2.0'
  AND REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) < '2.17.0';
\`\`\`

Expected: solr-kb and solr-support return log4j-core-2.14.1.jar. solr-catalog does not match.

---

## SSH quick reference

\`\`\`bash
# Attacker
ssh -i ${SSH_KEY} ubuntu@${REDTEAM_PUB}

# Solr hosts
ssh -i ${SSH_KEY} ubuntu@${SOLR_KB_PUB}       # solr-kb (vulnerable)
ssh -i ${SSH_KEY} ubuntu@${SOLR_SUPPORT_PUB}   # solr-support (vulnerable)
ssh -i ${SSH_KEY} ubuntu@${SOLR_CATALOG_PUB}   # solr-catalog (patched)
\`\`\`

---

## Teardown

\`\`\`bash
cd ${TERRAFORM_DIR} && terraform destroy --auto-approve
\`\`\`
EOF

echo "Demo script generated: ${OUTPUT}"
