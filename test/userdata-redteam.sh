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
echo "siem-demo-redteam-01" > /etc/hostname
hostname siem-demo-redteam-01 2>/dev/null || true

# Update system
echo "[2/7] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Install dependencies
echo "[3/7] Installing dependencies..."
apt-get install -y -qq curl wget git build-essential libssl-dev \
  libreadline-dev zlib1g-dev nmap netcat-traditional postgresql \
  postgresql-contrib python3 python3-pip unzip jq

# Install Metasploit Framework
echo "[4/7] Installing Metasploit Framework..."
cd /tmp
curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Skip database init in Docker (needs running PostgreSQL)
echo "[5/7] Skipping Metasploit database init (no systemd)..."

# Install nuclei (for Log4Shell vulnerability scanning)
echo "[6/7] Installing nuclei..."
NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | tr -d 'v')
if [ -n "${NUCLEI_VERSION}" ] && [ "${NUCLEI_VERSION}" != "null" ]; then
  wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip
  unzip -o /tmp/nuclei.zip -d /usr/local/bin/
  chmod +x /usr/local/bin/nuclei
else
  echo "WARNING: Could not determine nuclei version, skipping install"
fi

# Create scripts directory for attack automation
echo "[7/7] Creating scripts directory..."
mkdir -p /home/ubuntu/scripts

# Verify installation
echo ""
echo "Verification:"
msfconsole --version || echo "Metasploit not available yet"
nmap --version | head -1
nuclei --version 2>/dev/null || echo "nuclei not available yet"

echo ""
echo "=========================================="
echo "Red Team VM Setup Complete!"
echo "Completed: $(date)"
echo "=========================================="
