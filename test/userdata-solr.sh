#!/bin/bash
set -e

# Log all output to file for debugging
exec > >(tee -a /var/log/siem-demo-setup.log)
exec 2>&1

# Test values (normally injected by Terraform)
HOST_NAME="siem-demo-solr-kb"
ROLE_LABEL="Knowledge Base"
SOLR_VERSION="8.11.0"
JDK_URL="https://cdn.azul.com/zulu/bin/zulu8.31.0.1-jdk8.0.181-linux_x64.tar.gz"
JDK_DIR="zulu8.31.0.1-jdk8.0.181-linux_x64"
CORE_NAME="knowledge-base"

echo "=========================================="
echo "SIEM Demo - Host VM Setup"
echo "Apache Solr ${SOLR_VERSION} (${ROLE_LABEL})"
echo "Starting: $(date)"
echo "=========================================="

# Set hostname (skip in Docker — no systemd)
echo "[1/8] Setting hostname..."
echo "${HOST_NAME}" > /etc/hostname
hostname "${HOST_NAME}" 2>/dev/null || true

# Update system
echo "[2/8] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq wget curl net-tools lsof

# Install specific JDK version
echo "[3/8] Installing JDK from ${JDK_URL}..."
cd /tmp
for attempt in 1 2 3; do
  echo "  Download attempt $attempt/3..."
  wget -q --timeout=60 --tries=3 "${JDK_URL}" -O jdk.tar.gz && break
  echo "  Attempt $attempt failed, retrying in 10s..."
  sleep 10
done
if [ ! -s jdk.tar.gz ]; then
  echo "[ERROR] Failed to download JDK after all attempts"
  exit 1
fi
mkdir -p /opt/java
tar xzf jdk.tar.gz -C /opt/java
JAVA_HOME="/opt/java/${JDK_DIR}"

# Set JAVA_HOME system-wide
cat > /etc/profile.d/java.sh << 'JAVAENV'
export JAVA_HOME=/opt/java/JDKDIR
export PATH=$JAVA_HOME/bin:$PATH
JAVAENV
sed -i "s|JDKDIR|${JDK_DIR}|g" /etc/profile.d/java.sh
source /etc/profile.d/java.sh

# Verify Java
"${JAVA_HOME}/bin/java" -version 2>&1

# Create solr user
echo "[4/8] Creating solr user..."
if ! id "solr" &>/dev/null; then
  useradd -r -m -U -d /opt/solr-home -s /bin/bash solr
fi

# Configure passwordless sudo for solr (INTENTIONALLY INSECURE - for demo)
echo "solr ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/solr
chmod 440 /etc/sudoers.d/solr

# Download and install Solr
echo "[5/8] Downloading Apache Solr ${SOLR_VERSION}..."
SOLR_ARCHIVE="solr-${SOLR_VERSION}.tgz"
SOLR_URL="https://archive.apache.org/dist/lucene/solr/${SOLR_VERSION}/${SOLR_ARCHIVE}"

cd /tmp
wget -q "${SOLR_URL}"

# Extract and install using Solr's install script
echo "[6/8] Installing Solr..."
tar xzf "${SOLR_ARCHIVE}" "solr-${SOLR_VERSION}/bin/install_solr_service.sh" --strip-components=2

# Run install script with -n (don't start) since we don't have systemd
bash ./install_solr_service.sh "${SOLR_ARCHIVE}" \
  -i /opt \
  -d /var/solr \
  -u solr \
  -s solr \
  -p 8983 \
  -n

# Configure JAVA_HOME for Solr
echo "[7/8] Configuring Solr environment..."
cat >> /etc/default/solr.in.sh << SOLRENV
SOLR_JAVA_HOME="${JAVA_HOME}"
SOLR_HOST="0.0.0.0"
SOLRENV

# Start Solr manually (no systemd in Docker)
echo "[8/8] Starting Solr manually..."
export SOLR_JAVA_HOME="${JAVA_HOME}"
su - solr -c "SOLR_JAVA_HOME=${JAVA_HOME} /opt/solr/bin/solr start -p 8983 -h 0.0.0.0" || true

# Wait for Solr to start
echo "Waiting for Solr to start..."
for i in $(seq 1 30); do
  if curl -s "http://localhost:8983/solr/" > /dev/null 2>&1; then
    echo "Solr is up after ${i} seconds"
    break
  fi
  sleep 2
done

# Create a Solr core for the scenario
su - solr -c "/opt/solr/bin/solr create_core -c ${CORE_NAME} -d _default" || echo "Core creation may need retry"

# Get IP address
PRIVATE_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

# Verification
echo ""
echo "Verification:"
SOLR_VER=$(curl -s "http://localhost:8983/solr/admin/info/system" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['lucene']['solr-spec-version'])" 2>/dev/null || echo "unknown")
JAVA_VER=$("${JAVA_HOME}/bin/java" -version 2>&1 | head -1)

echo "Solr version: ${SOLR_VER}"
echo "Java version: ${JAVA_VER}"
echo "Core: ${CORE_NAME}"

echo ""
echo "=========================================="
echo "Host VM Setup Complete!"
echo "Hostname: $(hostname)"
echo "Role: ${ROLE_LABEL} (${CORE_NAME})"
echo "Solr Admin: http://${PRIVATE_IP}:8983/solr/"
echo "Completed: $(date)"
echo "=========================================="
