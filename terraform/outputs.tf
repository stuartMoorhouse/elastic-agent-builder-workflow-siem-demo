output "deployment_id" {
  description = "Elastic Cloud deployment ID"
  value       = ec_deployment.main.id
}

output "deployment_version" {
  description = "Elastic Stack version"
  value       = data.ec_stack.latest.version
}

output "elasticsearch_endpoint" {
  description = "Elasticsearch endpoint URL"
  value       = ec_deployment.main.elasticsearch.https_endpoint
  sensitive   = true
}

output "kibana_endpoint" {
  description = "Kibana endpoint URL"
  value       = ec_deployment.main.kibana.https_endpoint
  sensitive   = true
}

output "elasticsearch_username" {
  description = "Elasticsearch username"
  value       = ec_deployment.main.elasticsearch_username
}

output "elasticsearch_password" {
  description = "Elasticsearch password"
  value       = ec_deployment.main.elasticsearch_password
  sensitive   = true
}

output "integrations_server_endpoint" {
  description = "Integrations Server (Fleet) endpoint URL"
  value       = ec_deployment.main.integrations_server.https_endpoint
  sensitive   = true
}

# AWS Outputs

output "host_public_ips" {
  description = "Public IP addresses of the host VMs"
  value = {
    for i, instance in aws_instance.host :
    "host-0${i + 1}" => instance.public_ip
  }
}

output "redteam_public_ip" {
  description = "Public IP address of the red team VM"
  value       = aws_instance.redteam.public_ip
}

output "ssh_key_path" {
  description = "Path to the SSH private key file"
  value       = local_file.ssh_private_key.filename
}

output "ssh_command_hosts" {
  description = "SSH commands for host VMs"
  value = {
    for i, instance in aws_instance.host :
    "host-0${i + 1}" => "ssh -i ${local_file.ssh_private_key.filename} ec2-user@${instance.public_ip}"
  }
}

output "ssh_command_redteam" {
  description = "SSH command for red team VM"
  value       = "ssh -i ${local_file.ssh_private_key.filename} ec2-user@${aws_instance.redteam.public_ip}"
}
