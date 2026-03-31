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
  key_name   = "${local.prefix}-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_file" "ssh_private_key" {
  content         = tls_private_key.ssh.private_key_pem
  filename        = "${path.module}/../state/ssh-key.pem"
  file_permission = "0600"
}

# Per-host configuration for the Log4Shell scenario
# - solr-kb and solr-support: Solr 8.11.0 on old JDK 8u181 (VULNERABLE)
# All three hosts run Solr 8.11.0 on JDK 8u181 (VULNERABLE)
locals {
  host_configs = [
    {
      name         = "solr-kb"
      hostname     = "${local.prefix}-solr-kb"
      role_label   = "Knowledge Base"
      solr_version = "8.11.0"
      jdk_url      = "https://cdn.azul.com/zulu/bin/zulu8.31.0.1-jdk8.0.181-linux_x64.tar.gz"
      jdk_dir      = "zulu8.31.0.1-jdk8.0.181-linux_x64"
      core_name    = "knowledge-base"
    },
    {
      name         = "solr-support"
      hostname     = "${local.prefix}-solr-support"
      role_label   = "Support Portal"
      solr_version = "8.11.0"
      jdk_url      = "https://cdn.azul.com/zulu/bin/zulu8.31.0.1-jdk8.0.181-linux_x64.tar.gz"
      jdk_dir      = "zulu8.31.0.1-jdk8.0.181-linux_x64"
      core_name    = "support-portal"
    },
    {
      name         = "solr-catalog"
      hostname     = "${local.prefix}-solr-catalog"
      role_label   = "Product Catalog"
      solr_version = "8.11.0"
      jdk_url      = "https://cdn.azul.com/zulu/bin/zulu8.31.0.1-jdk8.0.181-linux_x64.tar.gz"
      jdk_dir      = "zulu8.31.0.1-jdk8.0.181-linux_x64"
      core_name    = "product-catalog"
    },
  ]
}

# Host VMs (Apache Solr instances — 2 vulnerable + 1 patched)
resource "aws_instance" "host" {
  count = length(local.host_configs)

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.aws_instance_type_host
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Log all output to file for debugging
              exec > >(tee -a /var/log/${local.prefix}-setup.log)
              exec 2>&1

              HOST_NAME="${local.host_configs[count.index].hostname}"
              ROLE_LABEL="${local.host_configs[count.index].role_label}"
              SOLR_VERSION="${local.host_configs[count.index].solr_version}"
              JDK_URL="${local.host_configs[count.index].jdk_url}"
              JDK_DIR="${local.host_configs[count.index].jdk_dir}"
              CORE_NAME="${local.host_configs[count.index].core_name}"

              echo "=========================================="
              echo "SIEM Demo - Host VM Setup"
              echo "Apache Solr $${SOLR_VERSION} ($${ROLE_LABEL})"
              echo "Starting: $(date)"
              echo "=========================================="

              # Set hostname
              echo "[1/8] Setting hostname..."
              hostnamectl set-hostname "$${HOST_NAME}"

              # Update system
              echo "[2/8] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq
              apt-get install -y -qq wget curl net-tools lsof

              # Install specific JDK version
              echo "[3/8] Installing JDK from $${JDK_URL}..."
              cd /tmp
              for attempt in 1 2 3; do
                echo "  Download attempt $attempt/3..."
                wget -q --timeout=60 --tries=3 "$${JDK_URL}" -O jdk.tar.gz && break
                echo "  Attempt $attempt failed, retrying in 10s..."
                sleep 10
              done
              if [ ! -s jdk.tar.gz ]; then
                echo "[ERROR] Failed to download JDK after all attempts"
                exit 1
              fi
              mkdir -p /opt/java
              tar xzf jdk.tar.gz -C /opt/java
              JAVA_HOME="/opt/java/$${JDK_DIR}"

              # Set JAVA_HOME system-wide
              cat > /etc/profile.d/java.sh << 'JAVAENV'
              export JAVA_HOME=/opt/java/JDKDIR
              export PATH=$JAVA_HOME/bin:$PATH
              JAVAENV
              sed -i "s|JDKDIR|$${JDK_DIR}|g" /etc/profile.d/java.sh
              source /etc/profile.d/java.sh

              # Verify Java
              "$${JAVA_HOME}/bin/java" -version 2>&1

              # Create solr user
              echo "[4/8] Creating solr user..."
              if ! id "solr" &>/dev/null; then
                useradd -r -m -U -d /opt/solr-home -s /bin/bash solr
              fi

              # Configure passwordless sudo for solr (INTENTIONALLY INSECURE - for demo)
              echo "solr ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/solr
              chmod 440 /etc/sudoers.d/solr

              # Download and install Solr
              echo "[5/8] Downloading Apache Solr $${SOLR_VERSION}..."
              SOLR_ARCHIVE="solr-$${SOLR_VERSION}.tgz"
              SOLR_URL="https://archive.apache.org/dist/lucene/solr/$${SOLR_VERSION}/$${SOLR_ARCHIVE}"

              cd /tmp
              wget -q "$${SOLR_URL}"

              # Extract and install using Solr's install script
              echo "[6/8] Installing Solr..."
              tar xzf "$${SOLR_ARCHIVE}" "solr-$${SOLR_VERSION}/bin/install_solr_service.sh" --strip-components=2
              bash ./install_solr_service.sh "$${SOLR_ARCHIVE}" \
                -i /opt \
                -d /var/solr \
                -u solr \
                -s solr \
                -p 8983 \
                -n

              # Configure JAVA_HOME for Solr
              echo "[7/8] Configuring Solr environment..."
              cat >> /etc/default/solr.in.sh << SOLRENV
              SOLR_JAVA_HOME="$${JAVA_HOME}"
              SOLR_HOST="0.0.0.0"
              SOLRENV

              # Start Solr
              systemctl enable solr
              systemctl start solr

              # Wait for Solr to start
              echo "[8/8] Waiting for Solr to start..."
              for i in $(seq 1 30); do
                if curl -s "http://localhost:8983/solr/" > /dev/null 2>&1; then
                  echo "Solr is up after $${i} seconds"
                  break
                fi
                sleep 2
              done

              # Create a Solr core for the scenario
              su - solr -c "/opt/solr/bin/solr create_core -c $${CORE_NAME} -d _default" || echo "Core creation may need retry"

              # Get IP address
              PRIVATE_IP=$(hostname -I | awk '{print $1}')

              # Verification
              echo ""
              echo "Verification:"
              if systemctl is-active --quiet solr; then
                echo "Solr is running"
              else
                echo "Solr failed to start"
              fi

              SOLR_VER=$(curl -s "http://localhost:8983/solr/admin/info/system" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['lucene']['solr-spec-version'])" 2>/dev/null || echo "unknown")
              JAVA_VER=$("$${JAVA_HOME}/bin/java" -version 2>&1 | head -1)

              echo "Solr version: $${SOLR_VER}"
              echo "Java version: $${JAVA_VER}"
              echo "Core: $${CORE_NAME}"

              echo ""
              echo "=========================================="
              echo "Host VM Setup Complete!"
              echo "Hostname: $(hostname)"
              echo "Role: $${ROLE_LABEL} ($${CORE_NAME})"
              echo "Solr Admin: http://$${PRIVATE_IP}:8983/solr/"
              echo "Completed: $(date)"
              echo "=========================================="
              EOF

  tags = {
    Name = local.host_configs[count.index].hostname
    Role = local.host_configs[count.index].name
  }
}

# Red Team VM (Metasploit + nmap + nuclei)
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

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = <<-EOF
              #!/bin/bash
              # Do NOT use set -e globally — individual steps handle their own errors
              # so that a transient failure in one tool doesn't abort the entire setup.

              # Log all output to file for debugging
              exec > >(tee -a /var/log/${local.prefix}-setup.log)
              exec 2>&1

              echo "=========================================="
              echo "SIEM Demo - Red Team VM Setup"
              echo "Starting: $(date)"
              echo "=========================================="

              SETUP_ERRORS=0

              # Set hostname
              echo "[1/7] Setting hostname..."
              hostnamectl set-hostname ${local.prefix}-redteam-01

              # Update system
              echo "[2/7] Updating system packages..."
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get upgrade -y -qq

              # Install dependencies (required — abort if this fails)
              echo "[3/7] Installing dependencies..."
              if ! apt-get install -y -qq curl wget git build-essential libssl-dev \
                libreadline-dev zlib1g-dev nmap netcat-traditional postgresql \
                postgresql-contrib python3 python3-pip unzip jq; then
                echo "[FATAL] Failed to install base dependencies"
                exit 1
              fi

              # Install Metasploit Framework (with retries)
              echo "[4/7] Installing Metasploit Framework..."
              cd /tmp
              MSF_INSTALLED=false
              for attempt in 1 2 3; do
                echo "  Metasploit install attempt $${attempt}/3..."
                curl --fail --retry 3 --retry-delay 5 -sS \
                  https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
                  -o msfinstall
                if [ ! -s msfinstall ]; then
                  echo "  Download produced empty file, retrying in 15s..."
                  sleep 15
                  continue
                fi
                chmod 755 msfinstall
                if ./msfinstall; then
                  MSF_INSTALLED=true
                  break
                fi
                echo "  Installer failed, retrying in 15s..."
                sleep 15
              done
              if [ "$${MSF_INSTALLED}" = false ]; then
                echo "[ERROR] Metasploit installation failed after 3 attempts"
                SETUP_ERRORS=$((SETUP_ERRORS + 1))
              fi

              # Initialize Metasploit database
              echo "[5/7] Initializing Metasploit database..."
              if [ "$${MSF_INSTALLED}" = true ]; then
                su - ubuntu -c "msfdb init" || echo "Note: msfdb init failed (run 'msfdb init' manually after login)"
              else
                echo "  Skipped — Metasploit not installed"
              fi

              # Install nuclei (for Log4Shell vulnerability scanning)
              echo "[6/7] Installing nuclei..."
              NUCLEI_VERSION=$(curl --fail --retry 3 -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | tr -d 'v')
              if [ -n "$${NUCLEI_VERSION}" ] && [ "$${NUCLEI_VERSION}" != "null" ]; then
                if wget -q --timeout=60 --tries=3 \
                  "https://github.com/projectdiscovery/nuclei/releases/download/v$${NUCLEI_VERSION}/nuclei_$${NUCLEI_VERSION}_linux_amd64.zip" \
                  -O /tmp/nuclei.zip && [ -s /tmp/nuclei.zip ]; then
                  unzip -o /tmp/nuclei.zip -d /usr/local/bin/
                  chmod +x /usr/local/bin/nuclei
                  su - ubuntu -c "nuclei -update-templates 2>/dev/null" || echo "Note: nuclei templates will download on first run"
                else
                  echo "WARNING: nuclei download failed"
                  SETUP_ERRORS=$((SETUP_ERRORS + 1))
                fi
              else
                echo "WARNING: Could not determine nuclei version, skipping install"
                SETUP_ERRORS=$((SETUP_ERRORS + 1))
              fi

              # Create scripts directory for attack automation
              echo "[7/7] Creating scripts directory..."
              mkdir -p /home/ubuntu/scripts
              chown ubuntu:ubuntu /home/ubuntu/scripts

              # Verify installation
              echo ""
              echo "Verification:"
              msfconsole --version 2>/dev/null || echo "MISSING: msfconsole"
              nmap --version | head -1 || echo "MISSING: nmap"
              nuclei --version 2>/dev/null || echo "MISSING: nuclei"

              echo ""
              echo "=========================================="
              if [ $${SETUP_ERRORS} -gt 0 ]; then
                echo "Red Team VM Setup COMPLETED WITH $${SETUP_ERRORS} ERROR(S)"
              else
                echo "Red Team VM Setup Complete!"
              fi
              echo "Completed: $(date)"
              echo "=========================================="
              EOF

  tags = {
    Name = "${local.prefix}-redteam-01"
    Role = "red-team"
  }
}

# Provision attack script to Red Team VM
resource "null_resource" "redteam_scripts" {
  depends_on = [aws_instance.redteam]

  triggers = {
    host_scan_hash = filemd5("${path.module}/scripts/host-scan.sh")
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

  # Copy attack script
  provisioner "file" {
    source      = "${path.module}/scripts/host-scan.sh"
    destination = "/home/ubuntu/scripts/host-scan.sh"

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
      "chmod +x /home/ubuntu/scripts/host-scan.sh",
      "echo 'Attack script installed: /home/ubuntu/scripts/host-scan.sh'",
    ]

    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = tls_private_key.ssh.private_key_pem
      host        = aws_instance.redteam.public_ip
    }
  }
}

# Deploy Elastic Agent to all host VMs
# Runs locally — the script reads terraform outputs and SSHes into each host.
resource "null_resource" "deploy_elastic_agent" {
  depends_on = [
    ec_deployment.main,
    terraform_data.kibana_default_space_security,
    aws_instance.host,
    null_resource.redteam_scripts,
  ]

  triggers = {
    script_hash = filemd5("${path.module}/scripts/deploy-elastic-agent.sh")
  }

  provisioner "local-exec" {
    command     = "bash ${path.module}/scripts/deploy-elastic-agent.sh"
    working_dir = path.module
  }
}

# Deploy Agent Builder agent + workflow via Kibana/ES APIs
# Runs locally after Elastic Agent is deployed (needs the Fleet policy to exist).
resource "null_resource" "deploy_workflow" {
  depends_on = [null_resource.deploy_elastic_agent]

  triggers = {
    script_hash = filemd5("${path.module}/scripts/deploy-workflow.sh")
  }

  provisioner "local-exec" {
    command     = "bash ${path.module}/scripts/deploy-workflow.sh"
    working_dir = path.module
  }
}

# Generate the presenter's demo script with actual IPs and URLs
resource "null_resource" "generate_demo_script" {
  depends_on = [null_resource.deploy_workflow]

  triggers = {
    script_hash = filemd5("${path.module}/scripts/generate-demo-script.sh")
    host_ips    = jsonencode([for i in aws_instance.host : i.public_ip])
    redteam_ip  = aws_instance.redteam.public_ip
  }

  provisioner "local-exec" {
    command     = "bash ${path.module}/scripts/generate-demo-script.sh"
    working_dir = path.module
  }
}
