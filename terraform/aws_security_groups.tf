resource "aws_security_group" "host" {
  name        = "siem-demo-host"
  description = "Security group for SIEM demo host VMs"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "siem-demo-host-sg"
  }
}

resource "aws_security_group" "redteam" {
  name        = "siem-demo-redteam"
  description = "Security group for SIEM demo red team VM"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "siem-demo-redteam-sg"
  }
}

# Host SG rules

resource "aws_vpc_security_group_ingress_rule" "host_ssh" {
  security_group_id = aws_security_group.host.id
  description       = "SSH from allowed CIDR"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = local.allowed_ssh_cidr
}

resource "aws_vpc_security_group_ingress_rule" "host_from_redteam" {
  security_group_id            = aws_security_group.host.id
  description                  = "All traffic from red team"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.redteam.id
}

resource "aws_vpc_security_group_ingress_rule" "host_from_hosts" {
  security_group_id            = aws_security_group.host.id
  description                  = "All traffic from other hosts"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.host.id
}

resource "aws_vpc_security_group_egress_rule" "host_all_out" {
  security_group_id = aws_security_group.host.id
  description       = "All outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Red team SG rules

resource "aws_vpc_security_group_ingress_rule" "redteam_ssh" {
  security_group_id = aws_security_group.redteam.id
  description       = "SSH from allowed CIDR"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = local.allowed_ssh_cidr
}

resource "aws_vpc_security_group_ingress_rule" "redteam_from_hosts" {
  security_group_id            = aws_security_group.redteam.id
  description                  = "All traffic from hosts (reverse shells)"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.host.id
}

resource "aws_vpc_security_group_egress_rule" "redteam_all_out" {
  security_group_id = aws_security_group.redteam.id
  description       = "All outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
