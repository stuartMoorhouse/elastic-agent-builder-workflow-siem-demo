# Data source to get latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = [var.aws_ami_owner]

  filter {
    name   = "name"
    values = [var.aws_ami_name_filter]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# SSH Key Pair
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

# Host VMs (3x vulnerable Tomcat servers)
resource "aws_instance" "host" {
  count = 3

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.aws_instance_type_host
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Log all output to file for debugging
              exec > >(tee -a /var/log/siem-demo-setup.log)
              exec 2>&1

              echo "=========================================="
              echo "SIEM Demo - Host VM Setup"
              echo "Vulnerable Tomcat Server Installation"
              echo "Starting: $(date)"
              echo "=========================================="

              # Set hostname
              echo "[1/8] Setting hostname..."
              hostnamectl set-hostname siem-demo-host-0${count.index + 1}

              # Update system
              echo "[2/8] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq

              # Install Java 11
              echo "[3/8] Installing Java 11..."
              apt-get install -y -qq openjdk-11-jdk wget curl net-tools

              # Create tomcat user
              echo "[4/8] Creating tomcat user..."
              if ! id "tomcat" &>/dev/null; then
                useradd -r -m -U -d /opt/tomcat -s /bin/false tomcat
              fi

              # Configure passwordless sudo for tomcat (INTENTIONALLY INSECURE - for demo)
              echo "tomcat ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/tomcat
              chmod 440 /etc/sudoers.d/tomcat

              # Download and install Tomcat 9.0.30 (VULNERABLE VERSION)
              echo "[5/8] Downloading Tomcat 9.0.30..."
              TOMCAT_VERSION="9.0.30"
              TOMCAT_ARCHIVE="apache-tomcat-$${TOMCAT_VERSION}.tar.gz"
              TOMCAT_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v$${TOMCAT_VERSION}/bin/$${TOMCAT_ARCHIVE}"

              cd /tmp
              wget -q "$${TOMCAT_URL}"

              # Extract and install
              echo "[6/8] Installing Tomcat..."
              mkdir -p /opt/tomcat
              tar xzf "$${TOMCAT_ARCHIVE}" -C /opt/tomcat --strip-components=1
              chown -R tomcat:tomcat /opt/tomcat/
              chmod -R u+x /opt/tomcat/bin/

              # Configure WEAK credentials (INTENTIONALLY INSECURE)
              echo "[7/8] Configuring weak credentials (tomcat/tomcat)..."
              cat > /opt/tomcat/conf/tomcat-users.xml << 'TOMCATUSERS'
              <?xml version="1.0" encoding="UTF-8"?>
              <tomcat-users xmlns="http://tomcat.apache.org/xml"
                            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                            xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
                            version="1.0">
                <role rolename="manager-gui"/>
                <role rolename="manager-script"/>
                <role rolename="manager-jmx"/>
                <role rolename="manager-status"/>
                <role rolename="admin-gui"/>
                <role rolename="admin-script"/>
                <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script"/>
              </tomcat-users>
              TOMCATUSERS

              # Remove remote access restrictions (INTENTIONALLY INSECURE)
              cat > /opt/tomcat/webapps/manager/META-INF/context.xml << 'MANAGERCTX'
              <?xml version="1.0" encoding="UTF-8"?>
              <Context antiResourceLocking="false" privileged="true" >
                <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>
              </Context>
              MANAGERCTX

              if [ -f /opt/tomcat/webapps/host-manager/META-INF/context.xml ]; then
                cat > /opt/tomcat/webapps/host-manager/META-INF/context.xml << 'HOSTCTX'
              <?xml version="1.0" encoding="UTF-8"?>
              <Context antiResourceLocking="false" privileged="true" >
                <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>
              </Context>
              HOSTCTX
              fi

              # Create systemd service
              echo "[8/8] Creating systemd service..."
              cat > /etc/systemd/system/tomcat.service << 'TOMCATSVC'
              [Unit]
              Description=Apache Tomcat Web Application Container
              After=network.target

              [Service]
              Type=forking
              User=tomcat
              Group=tomcat

              Environment="JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64"
              Environment="JAVA_OPTS=-Djava.security.egd=file:///dev/urandom -Djava.awt.headless=true"
              Environment="CATALINA_BASE=/opt/tomcat"
              Environment="CATALINA_HOME=/opt/tomcat"
              Environment="CATALINA_PID=/opt/tomcat/temp/tomcat.pid"
              Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

              ExecStart=/opt/tomcat/bin/startup.sh
              ExecStop=/opt/tomcat/bin/shutdown.sh

              RestartSec=10
              Restart=always

              [Install]
              WantedBy=multi-user.target
              TOMCATSVC

              # Start Tomcat
              systemctl daemon-reload
              systemctl enable tomcat
              systemctl start tomcat

              # Wait for Tomcat to start
              sleep 10

              # Get IP address
              PRIVATE_IP=$(hostname -I | awk '{print $1}')

              # Verification
              echo ""
              echo "Verification:"
              if systemctl is-active --quiet tomcat; then
                echo "Tomcat is running"
              else
                echo "Tomcat failed to start"
              fi

              if curl -s http://localhost:8080 > /dev/null 2>&1; then
                echo "Tomcat responds on port 8080"
              else
                echo "Tomcat is not responding"
              fi

              HTTP_CODE=$(curl -s -o /dev/null -w "%%{http_code}" -u tomcat:tomcat http://localhost:8080/manager/text/list 2>/dev/null || echo "000")
              if [ "$${HTTP_CODE}" = "200" ]; then
                echo "Manager application accessible"
              else
                echo "Manager returned HTTP $${HTTP_CODE}"
              fi

              echo ""
              echo "=========================================="
              echo "Host VM Setup Complete!"
              echo "Hostname: $(hostname)"
              echo "Tomcat Manager: http://$${PRIVATE_IP}:8080/manager/html"
              echo "Credentials: tomcat/tomcat"
              echo "Completed: $(date)"
              echo "=========================================="
              EOF

  tags = {
    Name = "siem-demo-host-0${count.index + 1}"
    Role = "host"
  }
}

# Red Team VM (Metasploit + attack tools)
resource "aws_instance" "redteam" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.aws_instance_type_redteam
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.redteam.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Log all output to file for debugging
              exec > >(tee -a /var/log/siem-demo-setup.log)
              exec 2>&1

              echo "=========================================="
              echo "SIEM Demo - Red Team VM Setup"
              echo "Starting: $(date)"
              echo "=========================================="

              # Set hostname
              echo "[1/7] Setting hostname..."
              hostnamectl set-hostname siem-demo-redteam-01

              # Update system
              echo "[2/7] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq

              # Install dependencies
              echo "[3/7] Installing dependencies..."
              apt-get install -y -qq curl wget git build-essential libssl-dev \
                libreadline-dev zlib1g-dev nmap netcat-traditional postgresql \
                postgresql-contrib python3 python3-pip

              # Install Metasploit Framework
              echo "[4/7] Installing Metasploit Framework..."
              cd /tmp
              curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
              chmod 755 msfinstall
              ./msfinstall

              # Initialize Metasploit database
              echo "[5/7] Initializing Metasploit database..."
              su - ubuntu -c "msfdb init" || echo "Note: Database initialization skipped (run 'msfdb init' manually after login)"

              # Install additional tools (nikto = directory/web scanner, john = password cracking)
              echo "[6/7] Installing additional tools..."
              apt-get install -y -qq john nikto dirb

              # Create scripts directory for attack automation
              echo "[7/7] Creating scripts directory..."
              mkdir -p /home/ubuntu/scripts
              chown ubuntu:ubuntu /home/ubuntu/scripts

              # Verify installation
              echo ""
              echo "Verification:"
              msfconsole --version || echo "Metasploit not available yet"
              nmap --version | head -1
              nikto -Version 2>/dev/null || echo "Nikto installed"

              echo ""
              echo "=========================================="
              echo "Red Team VM Setup Complete!"
              echo "Completed: $(date)"
              echo "=========================================="
              EOF

  tags = {
    Name = "siem-demo-redteam-01"
    Role = "red-team"
  }
}

# Provision attack script to Red Team VM
resource "null_resource" "redteam_scripts" {
  depends_on = [aws_instance.redteam]

  triggers = {
    script_hash = filemd5("${path.module}/../scripts/run-metasploit.sh")
  }

  # Wait for cloud-init to complete
  provisioner "remote-exec" {
    inline = [
      "echo 'Waiting for cloud-init to complete...'",
      "cloud-init status --wait || true",
      "mkdir -p /home/ubuntu/scripts",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.ssh.private_key_pem
      host        = aws_instance.redteam.public_ip
      timeout     = "10m"
    }
  }

  # Copy the attack script
  provisioner "file" {
    source      = "${path.module}/../scripts/run-metasploit.sh"
    destination = "/home/ubuntu/scripts/run-metasploit.sh"

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.ssh.private_key_pem
      host        = aws_instance.redteam.public_ip
    }
  }

  # Make script executable
  provisioner "remote-exec" {
    inline = [
      "chmod +x /home/ubuntu/scripts/run-metasploit.sh",
      "echo 'Attack script installed: /home/ubuntu/scripts/run-metasploit.sh'",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.ssh.private_key_pem
      host        = aws_instance.redteam.public_ip
    }
  }
}
