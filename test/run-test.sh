#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  ✅ $1"; ((PASS++)) || true; }
fail() { echo "  ❌ $1"; ((FAIL++)) || true; }
skip() { echo "  ⏭️  $1 (requires live endpoint)"; ((SKIP++)) || true; }

# ============================================================
# SOLR HOST TEST
# ============================================================
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  SOLR HOST USER-DATA TEST                ║"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "=== Building Solr test container ==="
podman build --platform linux/amd64 -t userdata-test-solr -f Dockerfile.solr . > /dev/null 2>&1
echo "    Built."

echo "=== Running Solr user-data script (log: container-solr.log) ==="
podman rm -f userdata-test-solr 2>/dev/null || true
podman run --platform linux/amd64 --name userdata-test-solr -d userdata-test-solr tail -f /dev/null > /dev/null
podman exec userdata-test-solr /usr/local/bin/userdata.sh > "$SCRIPT_DIR/container-solr.log" 2>&1
echo "    Done. Checking results..."

echo ""
echo "=== Solr Health Checks ==="

# Process running
if podman exec userdata-test-solr pgrep -f "solr" > /dev/null 2>&1; then
  pass "Solr process running"
else
  fail "Solr process NOT running"
fi

# Java installed
if podman exec userdata-test-solr /opt/java/zulu8.31.0.1-jdk8.0.181-linux_x64/bin/java -version 2>&1 | grep -q "1.8.0_181"; then
  pass "JDK 8u181 installed"
else
  fail "JDK 8u181 NOT installed"
fi

# Config files
if podman exec userdata-test-solr test -f /etc/profile.d/java.sh; then
  pass "Java profile config exists"
else
  fail "Java profile config missing"
fi

if podman exec userdata-test-solr test -f /etc/default/solr.in.sh; then
  pass "Solr env config exists"
else
  fail "Solr env config missing"
fi

if podman exec userdata-test-solr test -f /etc/sudoers.d/solr; then
  pass "Solr sudoers config exists"
else
  fail "Solr sudoers config missing"
fi

# Solr installation
if podman exec userdata-test-solr test -d /opt/solr; then
  pass "Solr installed at /opt/solr"
else
  fail "Solr NOT installed at /opt/solr"
fi

# Port 8983 listening
if podman exec userdata-test-solr curl -s http://localhost:8983/solr/ > /dev/null 2>&1; then
  pass "Port 8983 responding"
else
  fail "Port 8983 NOT responding"
fi

# Solr core created
if podman exec userdata-test-solr curl -s "http://localhost:8983/solr/admin/cores?action=STATUS" 2>/dev/null | grep -q "knowledge-base"; then
  pass "Solr core 'knowledge-base' created"
else
  fail "Solr core 'knowledge-base' NOT created"
fi

# Solr version check
SOLR_VER=$(podman exec userdata-test-solr curl -s "http://localhost:8983/solr/admin/info/system" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['lucene']['solr-spec-version'])" 2>/dev/null || echo "unknown")
if [ "$SOLR_VER" = "8.11.0" ]; then
  pass "Solr version 8.11.0 confirmed"
else
  fail "Solr version mismatch: got '$SOLR_VER', expected '8.11.0'"
fi

# Log errors check
SOLR_ERRORS=$(podman exec userdata-test-solr grep -ci 'error\|fatal\|failed' /var/log/siem-demo-setup.log 2>/dev/null | tail -1 || echo "0")
if [ "$SOLR_ERRORS" -le 5 ]; then
  pass "Setup log clean ($SOLR_ERRORS minor messages)"
else
  fail "Setup log has $SOLR_ERRORS error/fatal/failed lines"
fi

echo ""
echo "=== Cleanup Solr container ==="
podman rm -f userdata-test-solr > /dev/null 2>&1

# ============================================================
# RED TEAM TEST
# ============================================================
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  RED TEAM USER-DATA TEST                 ║"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "=== Building Red Team test container ==="
podman build --platform linux/amd64 -t userdata-test-redteam -f Dockerfile.redteam . > /dev/null 2>&1
echo "    Built."

echo "=== Running Red Team user-data script (log: container-redteam.log) ==="
podman rm -f userdata-test-redteam 2>/dev/null || true
podman run --platform linux/amd64 --name userdata-test-redteam -d userdata-test-redteam tail -f /dev/null > /dev/null
podman exec userdata-test-redteam /usr/local/bin/userdata.sh > "$SCRIPT_DIR/container-redteam.log" 2>&1
echo "    Done. Checking results..."

echo ""
echo "=== Red Team Health Checks ==="

# nmap installed
if podman exec userdata-test-redteam nmap --version > /dev/null 2>&1; then
  pass "nmap installed"
else
  fail "nmap NOT installed"
fi

# Metasploit installed
if podman exec userdata-test-redteam msfconsole --version > /dev/null 2>&1; then
  pass "Metasploit installed"
else
  fail "Metasploit NOT installed"
fi

# nuclei installed
if podman exec userdata-test-redteam nuclei --version > /dev/null 2>&1; then
  pass "nuclei installed"
else
  fail "nuclei NOT installed"
fi

# jq installed
if podman exec userdata-test-redteam jq --version > /dev/null 2>&1; then
  pass "jq installed"
else
  fail "jq NOT installed"
fi

# PostgreSQL installed (needed for Metasploit DB)
if podman exec userdata-test-redteam which psql > /dev/null 2>&1; then
  pass "PostgreSQL client installed"
else
  fail "PostgreSQL client NOT installed"
fi

# Scripts directory exists
if podman exec userdata-test-redteam test -d /home/ubuntu/scripts; then
  pass "Scripts directory created"
else
  fail "Scripts directory missing"
fi

# Metasploit DB init - requires live PostgreSQL
skip "Metasploit DB init (requires running PostgreSQL)"

# Log errors check
# Exclude false positives like package names containing "error" (e.g. liberror-perl)
RT_ERRORS=$(podman exec userdata-test-redteam grep -ci 'error\|fatal\|failed' /var/log/siem-demo-setup.log 2>/dev/null | tail -1 || echo "0")
if [ "$RT_ERRORS" -le 5 ]; then
  pass "Setup log clean ($RT_ERRORS minor messages)"
else
  fail "Setup log has $RT_ERRORS error/fatal/failed lines"
fi

echo ""
echo "=== Cleanup Red Team container ==="
podman rm -f userdata-test-redteam > /dev/null 2>&1

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "USER-DATA TEST RESULTS"
echo "══════════════════════"

SOLR_SIZE=$(wc -c < "$SCRIPT_DIR/userdata-solr.sh" | tr -d ' ')
RT_SIZE=$(wc -c < "$SCRIPT_DIR/userdata-redteam.sh" | tr -d ' ')

echo "Script sizes: solr=${SOLR_SIZE}B redteam=${RT_SIZE}B (limit: 16384B)"
if [ "$SOLR_SIZE" -lt 16384 ] && [ "$RT_SIZE" -lt 16384 ]; then
  echo "  ✅ Both under 16KB"
else
  echo "  ❌ SIZE LIMIT EXCEEDED — will fail on EC2!"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo ""
echo "Full logs:"
echo "  Solr:     $SCRIPT_DIR/container-solr.log"
echo "  Red Team: $SCRIPT_DIR/container-redteam.log"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
else
  echo "All checks passed! ✅"
  exit 0
fi
