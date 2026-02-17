# Security Incident Report

**TLP:AMBER -- LIMITED DISTRIBUTION**

- **Report ID:** IR-YYYY-MMDD-001
- **Severity:** [Critical / High / Medium / Low]
- **Status:** Open
- **Date:** YYYY-MM-DDTHH:MM:SSZ
- **Prepared By:** Elastic Workflow (automated)

## 1. Executive Summary

[2-3 sentences. What happened, how it was detected, confirmed scope, and current status. Write for leadership -- avoid jargon.]

> **SEVERITY: [LEVEL]** -- [One sentence: required action and deadline.]

## 2. Alert Details

- **Alert Source:** Elastic Defend
- **Alert Rule:** [from alert data: kibana.alert.rule.name]
- **Hostname:** [from alert data: host.name]
- **Host IP:** [from alert data: host.ip]
- **Host OS:** [from alert data: host.os.name and version]
- **Timestamp:** [from alert data: @timestamp]
- **Severity:** [from alert data: kibana.alert.severity]
- **MITRE ATT&CK:** [technique IDs and names from analysis]

### Process Tree

```
[parent process name] (PID [parent PID]) [parent executable]
  -> [child process name] (PID [child PID]) [child executable]
     Args: [process args]
```

### Network Activity

- **Direction:** [from alert data: network.direction]
- **Destination:** [from alert data: destination.ip]:[destination.port]
- **Transport:** [from alert data: network.transport]

## 3. Vulnerability Identified

- **CVE:** [CVE ID]
- **Common Name:** [if applicable]
- **CVSS Score:** [score and severity]
- **Affected Component:** [library/application with version range]
- **Fixed In:** [version]
- **Exploit Status:** [from analysis -- PoC / Weaponized / Actively exploited]

[1-2 sentence description of how the vulnerability works.]

## 4. Fleet Scan Results

List each affected host from the fleet scan data. Map column names to values.

For each host:
- **Hostname:** [host.name]
- **Path:** [path]

**Summary:** [N] hosts confirmed vulnerable out of [total scanned].

## 5. Indicators of Compromise

Extract from alert data and analysis. Only include IOCs actually present in the data.

- **[Type]:** `[value]` -- [context]
- **[Type]:** `[value]` -- [context]
- **[Type]:** `[value]` -- [context]

**Exploitation Status:** [ACTIVE EXPLOITATION CONFIRMED / VULNERABILITY PRESENT -- NO EXPLOITATION EVIDENCE]

[One sentence basis for this determination.]

## 6. Recommended Actions

**Immediate (0-24 hours):**
1. [action]
2. [action]
3. [action]

**Short-term (24-72 hours):**
4. [action]
5. [action]

**Ongoing:**
6. [action]
7. [action]

## 7. Detection Query

**Platform:** Elastic osquery

```sql
[exact SQL query as provided]
```

---

*END OF REPORT -- TLP:AMBER*
