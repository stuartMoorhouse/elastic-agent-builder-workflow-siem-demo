# Log4Shell SIEM Demo

Purple team demo: Log4Shell (CVE-2021-44228) exploitation of Apache Solr, detected by Elastic Defend, triaged automatically by an Elastic Workflow with AI agents.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  AWS VPC — 10.0.1.0/24 (eu-north-1)                                │
│                                                                     │
│  ┌──────────────┐    exploit     ┌──────────────────────────────┐   │
│  │  Red Team VM  │──────────────→│  solr-kb      (VULNERABLE)   │   │
│  │  Metasploit   │  reverse shell│  Solr 8.11.0 / JDK 8u181    │   │
│  │  nmap, nuclei │←──────────────│  Elastic Agent + Defend      │   │
│  └──────────────┘                └──────────────────────────────┘   │
│         │                        ┌──────────────────────────────┐   │
│         │  (same vulnerability)  │  solr-support  (VULNERABLE)  │   │
│         └───────────────────────→│  Solr 8.11.0 / JDK 8u181    │   │
│                                  │  Elastic Agent + Defend      │   │
│                                  └──────────────────────────────┘   │
│                                  ┌──────────────────────────────┐   │
│                                  │  solr-catalog  (PATCHED)     │   │
│                                  │  Solr 8.11.1 / JDK 8u352    │   │
│                                  │  Elastic Agent + Defend      │   │
│                                  └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
          │ alerts                           │ agent telemetry
          ▼                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Elastic Cloud (gcp-us-central1)                                    │
│                                                                     │
│  Elasticsearch ← Fleet Server ← Elastic Agents                     │
│       │                                                             │
│       ▼                                                             │
│  Detection Rule: "Shell Spawned by Java Process"                    │
│       │                                                             │
│       ▼                                                             │
│  Workflow: Alert Triage                                              │
│    1. AI agent analyzes alert → identifies Log4Shell                │
│    2. Generates osquery → scans fleet for vulnerable Log4j JARs    │
│    3. Indexes incident report → siem-demo-reports                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Pre-Demo Checklist

Run these before every demo to confirm the environment is ready.

```bash
cd terraform

# 1. VMs are reachable
terraform output -raw ssh_command_redteam | xargs -I{} ssh -o ConnectTimeout=5 {} "echo 'Red team VM: OK'"
terraform output -json ssh_command_hosts | jq -r '.[]' | while read cmd; do
  $cmd -o ConnectTimeout=5 "echo 'Host VM: OK'"
done

# 2. Solr is running on all 3 hosts
for ip in $(terraform output -json host_private_ips | jq -r '.[]'); do
  echo -n "$ip — Solr: "
  ssh -i ../state/ssh-key.pem -o ConnectTimeout=5 ubuntu@$(terraform output -raw redteam_public_ip) \
    "curl -sf http://$ip:8983/solr/admin/info/system | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d['lucene']['solr-spec-version'])\"" 2>/dev/null || echo "UNREACHABLE"
done

# 3. Agents are healthy (check Fleet in Kibana)
echo "Open Fleet: $(terraform output -raw kibana_endpoint)/app/fleet/agents"

# 4. No stale alerts from a previous run
echo "Open Alerts: $(terraform output -raw kibana_endpoint)/app/security/alerts"

# 5. Reset if needed (clears alerts, cases, processes)
../terraform/scripts/reset-demo.sh
```

Or the quick version — just open these two Kibana tabs:
- **Fleet → Agents** — 3 agents, all "Healthy"
- **Security → Alerts** — empty (or run `reset-demo.sh` to clear)

## Setup

### Prerequisites

- Terraform CLI installed
- AWS credentials configured (`aws configure` or environment variables)
- An Elastic Cloud API key (set via `EC_API_KEY` or in your Terraform variables)
- `jq` installed (used by helper scripts)

### Environment Variables

```bash
# Required — your public IP for SSH access (CIDR notation)
export TF_VAR_allowed_ssh_cidr="<YOUR_IP>/32"

# Optional — override defaults
export TF_VAR_aws_region="eu-north-1"           # default
export TF_VAR_region="gcp-us-central1"           # Elastic Cloud region, default
export TF_VAR_deployment_name="workflow-demo"     # default
```

### Deploy

```bash
cd terraform
terraform init
terraform apply
```

This takes ~10 minutes. Terraform provisions:
- An Elastic Cloud deployment (Elasticsearch, Kibana, Fleet, ML node)
- 3 Ubuntu VMs running Apache Solr (2 vulnerable, 1 patched) with Elastic Agent + Defend
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

### 1. SSH into the red team VM

```bash
# Terraform gives you the exact command:
$(cd terraform && terraform output -raw ssh_command_redteam)

# Or manually:
ssh -i state/ssh-key.pem ubuntu@$(cd terraform && terraform output -raw redteam_public_ip)
```

### 2. Run the attack

From the red team VM:

```bash
# Full recon + exploit (scans subnet, finds Solr, exploits Log4Shell)
./scripts/host-scan.sh -s 10.0.1.0/24 -a $(hostname -I | awk '{print $1}')

# Or skip recon and target solr-kb directly
./scripts/host-scan.sh -t <SOLR_KB_PRIVATE_IP> -a $(hostname -I | awk '{print $1}')
```

The script runs through: nmap discovery, Solr version fingerprinting, Log4Shell confirmation, Metasploit exploitation, and reverse shell.

You'll be dropped into an interactive Metasploit session on the victim.

### 3. Red team commands (in the reverse shell)

Once the reverse shell connects, run recon commands to generate Elastic Defend alerts:

```bash
whoami                          # solr — the service account
hostname                        # solr-kb
cat /etc/shadow                 # credential access (triggers alert)
sudo -l                         # privilege escalation check
find / -name "*.pem" 2>/dev/null  # secret hunting
ps aux | grep solr              # process enumeration
cat /opt/solr/server/etc/jetty.xml  # config file access
```

### 4. Observe in Kibana

- **Security → Alerts** — Defend alerts appear for the reverse shell, `/etc/shadow` read, etc.
- **Stack Management → Workflows** — The alert-triage workflow triggers automatically:
  1. AI agent analyzes the alert for likely vulnerability
  2. Generates an osquery to detect Log4Shell fleet-wide
  3. Runs the query across all monitored hosts
  4. Creates an incident report indexed to `siem-demo-reports`

---

## Talking Points

Use these to narrate each phase while commands run.

**During the attack (~90 seconds)**
> "The attacker already has network access — maybe from a phished VPN credential. They scan the subnet, find three Solr instances, and fingerprint versions. Two are running Solr 8.11.0 on an old JDK — classic Log4Shell targets. The third is patched and won't be exploitable. The script launches Metasploit's Log4Shell module, which injects a JNDI payload into a Solr HTTP header. Because the JDK is pre-8u191, it loads and executes a remote class — giving the attacker a reverse shell in about 30 seconds."

**During red team recon (in the shell)**
> "Now the attacker is on the box as the Solr service account. They're doing standard post-exploitation: checking privileges, reading `/etc/shadow`, hunting for credentials and keys. Every one of these actions is generating process telemetry that Elastic Defend is capturing in real time."

**Switching to Kibana (alerts)**
> "Within seconds, Defend fires alerts — shell spawned by Java, sensitive file access, credential reads. This is the detection side. But the real differentiator is what happens next."

**Showing the workflow**
> "The alert automatically triggers a workflow. An AI agent reads the alert, identifies Log4Shell as the likely vulnerability, then *writes an osquery on the fly* to scan every monitored host for vulnerable Log4j JARs. It runs that query across the fleet, finds the other unpatched host, and indexes a complete incident report — vulnerability identified, affected hosts listed, remediation steps. That entire triage process took about 60 seconds, no analyst intervention."

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

---

## Resetting the Demo

To run the demo again without rebuilding VMs (~30 seconds):

```bash
# From the project root (not the red team VM)
./terraform/scripts/reset-demo.sh
```

This kills attacker/victim processes, clears alerts and cases, resets detection rule suppression, and verifies agent health. It prints the attack command to run when ready.

---

## Teardown

```bash
cd terraform && terraform destroy
```
