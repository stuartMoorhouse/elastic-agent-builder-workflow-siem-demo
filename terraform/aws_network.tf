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

      # Wait for and clean up ENIs (GuardDuty Runtime Monitoring, slow-releasing instance ENIs, etc.)
      # Terraform may destroy EC2 instances concurrently, so we poll until all ENIs drain or
      # can be force-deleted. GuardDuty releases its ENIs shortly after instance termination.
      echo "Polling for ENIs in VPC ${self.triggers.vpc_id} (up to 3 minutes)..."
      MAX_WAIT=180
      WAITED=0
      while [ $WAITED -lt $MAX_WAIT ]; do
        ALL_ENIS=$(aws ec2 describe-network-interfaces \
          --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" \
          --query 'NetworkInterfaces[].[NetworkInterfaceId,Status,Attachment.AttachmentId]' \
          --output text \
          --region ${self.triggers.region} \
          $PROFILE_FLAG 2>/dev/null)
        if [ -z "$ALL_ENIS" ] || [ "$ALL_ENIS" = "None" ]; then
          echo "All ENIs cleared."
          break
        fi

        # Delete available (unattached) ENIs
        AVAIL_ENIS=$(aws ec2 describe-network-interfaces \
          --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" "Name=status,Values=available" \
          --query 'NetworkInterfaces[].NetworkInterfaceId' \
          --output text \
          --region ${self.triggers.region} \
          $PROFILE_FLAG 2>/dev/null)
        for ENI in $AVAIL_ENIS; do
          echo "Deleting available ENI: $ENI"
          aws ec2 delete-network-interface \
            --network-interface-id "$ENI" \
            --region ${self.triggers.region} \
            $PROFILE_FLAG 2>/dev/null || true
        done

        # Detach and delete in-use ENIs that are not owned by AWS services
        # (e.g. orphaned ENIs; GuardDuty ENIs will transition to available once instances terminate)
        INUSE_ENIS=$(aws ec2 describe-network-interfaces \
          --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" "Name=status,Values=in-use" \
          --query 'NetworkInterfaces[?RequesterManaged==`false`].[NetworkInterfaceId,Attachment.AttachmentId]' \
          --output text \
          --region ${self.triggers.region} \
          $PROFILE_FLAG 2>/dev/null)
        while IFS=$'\t' read -r ENI ATTACHMENT; do
          [ -z "$ENI" ] && continue
          if [ -n "$ATTACHMENT" ] && [ "$ATTACHMENT" != "None" ]; then
            echo "Detaching ENI $ENI (attachment $ATTACHMENT)..."
            aws ec2 detach-network-interface \
              --attachment-id "$ATTACHMENT" \
              --force \
              --region ${self.triggers.region} \
              $PROFILE_FLAG 2>/dev/null || true
            sleep 5
          fi
          aws ec2 delete-network-interface \
            --network-interface-id "$ENI" \
            --region ${self.triggers.region} \
            $PROFILE_FLAG 2>/dev/null || true
        done <<< "$INUSE_ENIS"

        echo "ENIs still present, waiting 15s ($${WAITED}s elapsed)..."
        sleep 15
        WAITED=$((WAITED + 15))
      done

      # Delete non-default security groups with retry.
      # GuardDuty-managed SGs fail if GuardDuty ENIs are still attached (instances terminating
      # concurrently). Retry for up to 5 minutes until GuardDuty releases its references.
      MAX_SG_WAIT=300
      SG_WAITED=0
      while [ $SG_WAITED -lt $MAX_SG_WAIT ]; do
        SG_IDS=$(aws ec2 describe-security-groups \
          --filters "Name=vpc-id,Values=${self.triggers.vpc_id}" \
          --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
          --output text \
          --region ${self.triggers.region} \
          $PROFILE_FLAG 2>/dev/null)
        if [ -z "$SG_IDS" ] || [ "$SG_IDS" = "None" ]; then
          echo "All non-default SGs deleted."
          break
        fi
        ALL_DELETED=true
        for SG in $SG_IDS; do
          echo "Deleting security group: $SG"
          if ! aws ec2 delete-security-group \
            --group-id "$SG" \
            --region ${self.triggers.region} \
            $PROFILE_FLAG 2>/dev/null; then
            echo "  SG $SG still has references, will retry..."
            ALL_DELETED=false
          fi
        done
        [ "$ALL_DELETED" = "true" ] && break
        echo "Waiting 30s for GuardDuty to release SG references ($${SG_WAITED}s elapsed)..."
        sleep 30
        SG_WAITED=$((SG_WAITED + 30))
      done
    EOT
  }
}
