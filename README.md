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

### Run just the attack (against existing Solr VM)

```bash
SSH_KEY=state/ssh-key.pem
ATTACKER=$(cd terraform && terraform output -raw redteam_public_ip)
TARGET=$(cd terraform && terraform output -json host_private_ips | jq -r '.["solr-kb"]')
ATTACKER_PRIV=$(cd terraform && terraform output -raw redteam_private_ip)

ssh -i $SSH_KEY ubuntu@$ATTACKER "bash /home/ubuntu/scripts/host-scan.sh -t $TARGET -a $ATTACKER_PRIV"
```

### Redeploy workflow only (after editing YAML or agents)

```bash
./terraform/scripts/deploy-workflow.sh
```

### Teardown workflows and cases

```bash
./terraform/scripts/teardown-workflow-and-cases.sh
```
