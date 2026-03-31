# Auto-detect the operator's public IP for SSH security group rules
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}

locals {
  allowed_ssh_cidr = var.allowed_ssh_cidr != "" ? var.allowed_ssh_cidr : "${trimspace(data.http.my_ip.response_body)}/32"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "${local.prefix}-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# GuardDuty Runtime Monitoring auto-creates VPC endpoints and security groups
# that aren't in Terraform state, blocking subnet/VPC deletion on destroy.
resource "null_resource" "vpc_guardduty_cleanup" {
  triggers = {
    vpc_id  = aws_vpc.main.id
    region  = var.aws_region
    profile = var.aws_profile
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      PROFILE_FLAG=""
      if [ -n "${self.triggers.profile}" ]; then
        PROFILE_FLAG="--profile ${self.triggers.profile}"
      fi

      # Delete VPC endpoints (e.g. GuardDuty runtime monitoring)
      ENDPOINTS=$(aws ec2 describe-vpc-endpoints \
        --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" \
        --query 'VpcEndpoints[].VpcEndpointId' \
        --output text \
        --region ${self.triggers.region} \
        $PROFILE_FLAG 2>/dev/null)
      if [ -n "$ENDPOINTS" ] && [ "$ENDPOINTS" != "None" ]; then
        echo "Cleaning up VPC endpoints: $ENDPOINTS"
        aws ec2 delete-vpc-endpoints \
          --vpc-endpoint-ids $ENDPOINTS \
          --region ${self.triggers.region} \
          $PROFILE_FLAG
        sleep 15
      fi

      # Delete non-default security groups (e.g. GuardDuty-managed)
      SG_IDS=$(aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" \
        --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
        --output text \
        --region ${self.triggers.region} \
        $PROFILE_FLAG 2>/dev/null)
      if [ -n "$SG_IDS" ] && [ "$SG_IDS" != "None" ]; then
        for SG in $SG_IDS; do
          echo "Deleting security group: $SG"
          aws ec2 delete-security-group \
            --group-id "$SG" \
            --region ${self.triggers.region} \
            $PROFILE_FLAG 2>/dev/null || true
        done
      fi
    EOT
  }
}
