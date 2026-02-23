# Log4Shell SIEM Demo

Purple team demo: Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) exploitation of Apache Solr, detected by Elastic Defend, triaged automatically by an Elastic Workflow with AI agents.

## Prerequisites

- Terraform CLI installed
- `jq` installed (used by helper scripts)
- AWS credentials as environment variables:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
- An Elastic Cloud API key (set via `EC_API_KEY` or in your Terraform variables)

### Environment Variables

```bash
# Optional — override defaults (SSH is auto-locked to your current public IP)
export TF_VAR_aws_region="eu-north-1"           # default
export TF_VAR_region="gcp-us-central1"           # Elastic Cloud region, default
export TF_VAR_deployment_name="workflow-demo"     # default
```

## Deploy

```bash
cd terraform
terraform init
```

All variables have usable defaults — you can run `terraform apply` without creating a `.tfvars` file. To customise, copy `terraform.tfvars.example` to `terraform.tfvars` and uncomment any lines you want to override (e.g. AWS profile, SSH IP, region).

```bash
terraform apply
```

Terraform provisions:
- An Elastic Cloud deployment (Elasticsearch, Kibana, Fleet, ML node)
- 3 Ubuntu VMs running Apache Solr (all vulnerable — Solr 8.11.0 / JDK 8u181) with Elastic Agent + Defend
- 1 red team VM with Metasploit, nmap, and nuclei
- Detection rules and the alert-triage workflow in Kibana

When complete, Terraform prints the SSH commands and Kibana URL you'll need.

### Verify

```bash
# Print all connection info
terraform output

# Open Kibana (copy the URL from output)
terraform output -raw kibana_endpoint

# Confirm 3 agents are healthy in Fleet
# Kibana → Fleet → Agents — all 3 should show "Healthy"
```

---

## Running the Demo

### 1. Launch the attack

From the `terraform/` directory — SSHs into the red team VM and exploits solr-kb:

```bash
$(terraform output -raw ssh_command_redteam) -t \
  "./scripts/host-scan.sh -t $(terraform output -json host_private_ips | jq -r '.["solr-kb"]') -a \$(hostname -I | awk '{print \$1}')"
```

The script runs through: nmap discovery, Solr version fingerprinting, Log4Shell confirmation, Metasploit exploitation, and reverse shell.

You'll be dropped into an interactive Metasploit session on the victim.

### 2. Observe in Kibana

- **Security → Alerts** — Defend alerts appear for the reverse shell, `/etc/shadow` read, etc.
- **Stack Management → Workflows** — The alert-triage workflow triggers automatically:
  1. AI agent analyzes the alert for likely vulnerability
  2. Generates an osquery to detect Log4Shell fleet-wide
  3. Runs the query across all monitored hosts
  4. Creates an incident report indexed to `siem-demo-reports`

---

## Resetting the Demo

To run the demo again without rebuilding VMs (from the same `terraform/` directory):

```bash
./scripts/reset-demo.sh
```

This kills attacker/victim processes, clears alerts and cases, resets detection rule suppression, and verifies agent health. It prints the attack command to run when ready.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  AWS VPC — 10.0.1.0/24 (eu-north-1)                                 │
│                                                                     │
│  ┌──────────────┐    exploit     ┌──────────────────────────────┐   │
│  │  Red Team VM │──────────────→ │  solr-kb      (VULNERABLE)   │   │
│  │  Metasploit  │  reverse shell │  Solr 8.11.0 / JDK 8u181     │   │
│  │  nmap, nuclei│←────────────── │  Elastic Agent + Defend      │   │
│  └──────────────┘                └──────────────────────────────┘   │
│         │                        ┌──────────────────────────────┐   │
│         │  (same vulnerability)  │  solr-support  (VULNERABLE)  │   │
│         └───────────────────────→│  Solr 8.11.0 / JDK 8u181     │   │
│         |                        │  Elastic Agent + Defend      │   │
│         |                        └──────────────────────────────┘   │
│         |                        ┌──────────────────────────────┐   │
│         |                        │  solr-catalog  (VULNERABLE)  │   │
│         └───────────────────────→|  Solr 8.11.0 / JDK 8u181     │   │
│                                  │  Elastic Agent + Defend      │   │
│                                  └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │ agent telemetry
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Elastic Cloud (gcp-us-central1)                                    │
│                                                                     │
│  Elasticsearch ← Fleet Server ← Elastic Agents                      │
│       │                                                             │
│       ▼                                                             │
│  Detection Rule: "Shell Spawned by Java Process"                    │
│       │                                                             │
│       ▼                                                             │
│  Workflow: Alert Triage                                             │
│    1. AI agent analyzes alert → identifies Log4Shell                │
│    2. Generates osquery → scans fleet for vulnerable Log4j JARs     │
│    3. Indexes incident report → siem-demo-reports                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

**No alerts appearing after the attack**
- Check Fleet → Agents — if an agent is "Unhealthy" or "Offline", the host isn't sending telemetry.
- If agents are healthy but no alerts: the detection rule may be disabled or suppressed from a previous run. Run `./terraform/scripts/reset-demo.sh` to clear suppression state.
- If Solr was restarted at any point (e.g., during debugging), the Elastic Defend eBPF sensor loses track of the Java process tree. The reset script detects this and restarts `ElasticEndpoint.service` automatically.

**Reverse shell doesn't connect**
- Verify the red team VM's security group allows inbound on ports 1389, 4444, and 8080 from the VPC subnet. Terraform configures this, but if you modified the security group manually, check it.
- Confirm Solr is running: `curl -s http://<HOST_PRIVATE_IP>:8983/solr/admin/info/system | jq .lucene` from the red team VM.

**Workflow doesn't trigger**
- The workflow triggers on the "Shell Spawned by Java Process" detection rule. Confirm the rule is enabled: Kibana → Security → Rules → search for "Shell Spawned".
- Check Stack Management → Workflows — the workflow should show recent executions. If it shows errors, click into the execution to see which step failed.

**Osquery step fails in the workflow**
- The osquery manager integration must be installed on the agent policy. Check Fleet → Agent Policies → the policy used by the Solr hosts → confirm "Osquery Manager" is listed.

**Checking VM software versions**

```bash
cd terraform

# Solr is running on all 3 hosts
for ip in $(terraform output -json host_private_ips | jq -r '.[]'); do
  echo -n "$ip — Solr: "
  ssh -i ../state/ssh-key.pem -o ConnectTimeout=5 ubuntu@$(terraform output -raw redteam_public_ip) \
    "curl -sf http://$ip:8983/solr/admin/info/system | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d['lucene']['solr-spec-version'])\"" 2>/dev/null || echo "UNREACHABLE"
done

# Agents are healthy (check Fleet in Kibana)
echo "Open Fleet: $(terraform output -raw kibana_endpoint)/app/fleet/agents"
```

---

## Teardown

```bash
cd terraform && terraform destroy
```
