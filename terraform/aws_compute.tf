resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "main" {
  key_name   = "siem-demo-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_file" "ssh_private_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = "${path.module}/../state/ssh-key.pem"
  file_permission = "0600"
}

resource "aws_instance" "host" {
  count = 3

  ami                    = var.aws_ami
  instance_type          = var.aws_instance_type_host
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]

  tags = {
    Name = "siem-demo-host-0${count.index + 1}"
  }
}

resource "aws_instance" "redteam" {
  ami                    = var.aws_ami
  instance_type          = var.aws_instance_type_redteam
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.redteam.id]

  tags = {
    Name = "siem-demo-redteam-01"
  }
}
