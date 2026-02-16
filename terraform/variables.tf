variable "deployment_name" {
  description = "Name of the Elastic Cloud deployment"
  type        = string
  default     = "workflow-demo"
}

variable "region" {
  description = "Elastic Cloud region"
  type        = string
  default     = "gcp-us-central1"
}

variable "deployment_template_id" {
  description = "Elastic Cloud deployment template ID"
  type        = string
  default     = "gcp-storage-optimized"
}

variable "elasticsearch_size" {
  description = "Elasticsearch node size"
  type        = string
  default     = "8g"
}

variable "elasticsearch_zone_count" {
  description = "Number of Elasticsearch availability zones"
  type        = number
  default     = 1
}

variable "kibana_size" {
  description = "Kibana node size"
  type        = string
  default     = "1g"
}

variable "kibana_zone_count" {
  description = "Number of Kibana availability zones"
  type        = number
  default     = 1
}

# AWS Variables

variable "aws_region" {
  description = "AWS region for EC2 instances"
  type        = string
  default     = "us-east-1"
}

variable "aws_tags" {
  description = "Default tags applied to all AWS resources"
  type        = map(string)
  default     = {}
}

variable "aws_instance_type_host" {
  description = "EC2 instance type for host VMs"
  type        = string
  default     = "t3.small"
}

variable "aws_instance_type_redteam" {
  description = "EC2 instance type for red team VM"
  type        = string
  default     = "t3.medium"
}

variable "aws_ami_owner" {
  description = "Owner ID for AMI lookup (Canonical for Ubuntu)"
  type        = string
  default     = "099720109477"
}

variable "aws_ami_name_filter" {
  description = "Name filter for AMI lookup"
  type        = string
  default     = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into instances (e.g. your IP/32)"
  type        = string
}
