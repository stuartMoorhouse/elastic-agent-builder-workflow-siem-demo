#!/bin/bash

################################################################################
# SIEM Demo - Reset Victim and Attacker VMs
#
# Recreates the solr-kb VM from scratch, installs Elastic Agent, and waits
# for event collection to start. Does NOT run the exploit — use this to
# prepare a clean environment before running the attack manually.
#
# Usage:
#   cd <project-root>
#   ./terraform/scripts/reset-solr-red-vm.sh
################################################################################

set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-common.sh"
trap 'cleanup_curl_auth' EXIT

################################################################################
# STEP 1: Read terraform outputs
################################################################################

print_phase "STEP 1: Reading Terraform outputs"
read_terraform_outputs
read_vm_ips
print_vm_ips

################################################################################
# STEP 2: Taint and recreate solr-kb VM
################################################################################

print_phase "STEP 2: Recreating solr-kb VM"
recreate_solr_kb

################################################################################
# STEP 3: Wait for cloud-init + Solr
################################################################################

print_phase "STEP 3: Waiting for cloud-init and Solr"
wait_for_solr_kb

################################################################################
# STEP 4: Install Elastic Agent on solr-kb
################################################################################

print_phase "STEP 4: Installing Elastic Agent"
install_agent_solr_kb

################################################################################
# STEP 5: Wait for event collection to start
################################################################################

print_phase "STEP 5: Waiting for process events to appear in Elasticsearch"
wait_for_process_events

################################################################################
# Ready
################################################################################

print_phase "Reset Complete"

print_info "VMs are ready for the demo."
echo ""
print_info "Run the attack with:"
echo ""
echo "  SSH_KEY=state/ssh-key.pem"
echo "  ATTACKER=\$(cd terraform && terraform output -raw redteam_public_ip)"
echo "  TARGET=\$(cd terraform && terraform output -json host_private_ips | jq -r '.\"solr-kb\"')"
echo "  ATTACKER_PRIV=\$(cd terraform && terraform output -raw redteam_private_ip)"
echo ""
echo "  ssh -t -i \$SSH_KEY ubuntu@\$ATTACKER \"bash /home/ubuntu/scripts/host-scan.sh -t \$TARGET -a \$ATTACKER_PRIV\""
echo ""
