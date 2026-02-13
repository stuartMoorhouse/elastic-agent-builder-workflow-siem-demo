# Elastic Security Workflows

**A Practical Guide to Automation**

Learn to build automated security workflows that respond to alerts, orchestrate AI agents, and integrate with external tools.

*Elastic 9.0+*

---

## Contents

1. [Introduction](#1-introduction)
2. [Your First Workflow](#2-your-first-workflow)
3. [Core Concepts](#3-core-concepts)
4. [Step Types Reference](#4-step-types-reference)
5. [Liquid Templating](#5-liquid-templating)
6. [Control Flow](#6-control-flow)
7. [Error Handling](#7-error-handling)
8. [Real-World Examples](#8-real-world-examples)
9. [Quick Reference](#9-quick-reference)
10. [Importing Workflows](#10-importing-workflows)

---

## 1. Introduction

### What Are Workflows?

Elastic Workflows provide a declarative YAML-based approach to automating operations across the Elastic platform. They integrate natively with Elasticsearch, Kibana, external systems, and AI/ML capabilities.

With workflows, you can:

- Automatically triage alerts and create cases
- Enrich alerts with data from external threat intelligence
- Isolate compromised hosts without manual intervention
- Notify your team via Slack, email, or other channels
- Orchestrate AI agents to analyze and respond to threats
- Query and aggregate data with ES|QL

### Key Features

- **Declarative YAML** — Define what you want, not how to do it
- **Multiple Triggers** — Manual, scheduled, or alert-driven
- **Extensible** — Connect to any HTTP API or Elastic feature
- **Version Control** — Store workflows as code, track changes in Git
- **Liquid Templating** — Dynamic content with powerful filters

### When to Use Workflows

Workflows excel at repetitive tasks that follow predictable patterns:

- **Alert enrichment**: Look up file hashes in VirusTotal, check IPs against threat feeds
- **Automated triage**: Create cases, add comments, assign to on-call analysts
- **Incident response**: Isolate hosts, collect forensic data, notify stakeholders
- **Detection validation**: Run adversary emulations and measure detection coverage
- **Scheduled reporting**: Daily security summaries, compliance checks

### Prerequisites

Before building workflows, you should be comfortable with:

- Basic YAML syntax (indentation matters!)
- Elastic Security concepts: alerts, cases, detection rules
- The Kibana interface for managing security content

---

## 2. Your First Workflow

Let's start with a simple workflow that prints a greeting. This introduces the basic structure.

### The Simplest Workflow

```yaml
name: hello_world
description: A simple greeting workflow

triggers:
  - type: manual

inputs:
  - name: username
    type: string
    required: true
    description: "The name of the user to greet"

steps:
  - name: print_greeting
    type: console
    with:
      message: "Hello, {{ inputs.username }}!"
```

### Breaking It Down

Every workflow has these main sections:

#### Metadata

**name**: A unique identifier for the workflow. **description**: Optional but recommended explanation of what the workflow does.

#### Triggers

Triggers define when the workflow runs. Manual triggers require a user to start them. We'll cover alert and scheduled triggers later.

#### Inputs

Inputs are parameters that users provide when running the workflow. Each input has a name, type, and optional default value.

#### Steps

Steps are the actions your workflow performs, executed in order. Each step has a name, type, and configuration under "with".

### Try It Yourself

1. Navigate to Management → Workflows in Kibana
2. Click "Create workflow"
3. Paste the YAML above
4. Save and run with your name as input
5. Check the execution log to see your greeting

---

## 3. Core Concepts

### Workflow Schema

Every workflow follows a consistent YAML schema:

```yaml
# Required fields
name: "Workflow Name"
steps:
  - name: "Step Name"
    type: "action.type"
    with:
      key: value

# Optional fields
description: "What this does"
tags:
  - security
  - enrichment
triggers:
  - type: manual
consts:
  api_key: "value"
inputs:
  - name: query
    type: string
    required: true
```

### Triggers

Triggers determine when your workflow executes. There are three types:

#### Manual Triggers

The simplest trigger. Users start the workflow from the UI or API.

```yaml
triggers:
  - type: manual
```

#### Alert Triggers

The workflow runs automatically when alerts fire. Alert data is available via the event object.

```yaml
triggers:
  - type: alert
```

With alert triggers, you access alert data like this:

```yaml
{{ event.alerts[0]['kibana.alert.rule.name'] }}
{{ event.alerts[0].file.hash.sha256 }}
{{ event.alerts[0].host.name }}
```

#### Scheduled Triggers

Run on a schedule using simple interval syntax:

```yaml
triggers:
  - type: scheduled
    with:
      every: "6h"    # Every 6 hours
```

Or using RRULE for more complex schedules:

```yaml
triggers:
  - type: scheduled
    with:
      rrule:
        freq: DAILY
        interval: 1
        byhour:
          - 9
        byminute:
          - 0
        tzid: UTC
```

### Constants

Store values that don't change between executions. Ideal for API keys, URLs, and connector IDs.

```yaml
consts:
  slack_webhook: "https://hooks.slack.com/..."
  kibana_url: "https://your-cluster.elastic-cloud.com"
  vt_api_key: "your-api-key-here"
```

> **Note:** For sensitive values like API keys, consider using Kibana's Webhook connector which stores credentials securely, rather than hardcoding them in the workflow YAML.

### Variable Syntax

Reference values using double curly braces:

```yaml
# Constants
url: "{{ consts.api_url }}/endpoint"

# Inputs
query: "host.ip: {{ inputs.target_ip }}"

# Step outputs
message: "Found {{ steps.search.output.hits.total }} results"
```

### Expression Syntax

Workflows use two expression syntaxes:

| Syntax | Use Case | Example |
|--------|----------|---------|
| `{{ }}` | String interpolation, Liquid templates | `{{ inputs.username }}` |
| `${{ }}` | Expressions, conditions, array passthrough | `${{ steps.check.output == 'yes' }}` |

---

## 4. Step Types Reference

### Console

Print messages to the execution log. Useful for debugging and audit trails.

```yaml
- name: log_info
  type: console
  with:
    message: "Processing alert: {{ event.alerts[0]._id }}"
```

### HTTP

Make HTTP requests to external APIs.

```yaml
- name: check_virustotal
  type: http
  with:
    url: "https://www.virustotal.com/api/v3/files/{{ inputs.hash }}"
    method: GET
    headers:
      x-apikey: "{{ consts.vt_api_key }}"
    timeout: 30s
```

Access the response in subsequent steps:

```yaml
{{ steps.check_virustotal.output.data.attributes.reputation }}
```

### Wait

Pause execution for a specified duration.

```yaml
- name: wait_for_processing
  type: wait
  with:
    duration: 30s
```

### Data Set

Store computed values for use in later steps.

```yaml
- name: store_count
  type: data.set
  with:
    row_count: "{{ steps.query.output.values | size }}"
    is_critical: "{{ steps.check.output.severity == 'critical' }}"
```

### AI Agent

Invoke an AI agent configured in Elastic's Agent Builder.

```yaml
- name: analyze_threat
  type: ai.agent
  with:
    agent_id: threat-analysis-agent
    message: "Analyze this alert: {{ event | json }}"
  timeout: 10m
```

### Elasticsearch Operations

#### ES|QL Query

```yaml
- name: query_alerts
  type: elasticsearch.esql.query
  with:
    format: json
    query: |
      FROM .alerts-security.alerts-default
      | WHERE @timestamp > NOW() - 24 hours
      | STATS alert_count = COUNT(*) BY host.name
      | SORT alert_count DESC
      | LIMIT 10
```

#### Elasticsearch Search

```yaml
- name: search_logs
  type: elasticsearch.search
  with:
    index: logs-*
    size: 100
    query:
      match:
        host.name: "{{ inputs.hostname }}"
```

#### Raw Elasticsearch Request

```yaml
- name: index_result
  type: elasticsearch.request
  with:
    method: PUT
    path: "/audit-logs/_doc/{{ execution.id }}"
    body:
      timestamp: "{{ execution.startedAt }}"
      workflow: "{{ workflow.id }}"
      result: "{{ steps.previous.output }}"
```

### Kibana Operations

#### Create a Case

```yaml
- name: create_case
  type: kibana.createCaseDefaultSpace
  with:
    owner: securitySolution
    title: "Alert: {{ event.alerts[0]['kibana.alert.rule.name'] }}"
    description: "Automated case for investigation"
    severity: high
    tags:
      - automated
      - triage
```

#### Add Case Comment

```yaml
- name: add_comment
  type: kibana.request
  with:
    method: POST
    path: "/api/cases/{{ steps.create_case.output.id }}/comments"
    body:
      type: user
      owner: securitySolution
      comment: "Analysis complete: {{ steps.ai_analysis.output.response.message }}"
```

#### Isolate a Host

```yaml
- name: isolate_host
  type: kibana.request
  with:
    method: POST
    path: /api/endpoint/action/isolate
    body:
      endpoint_ids:
        - "{{ event.alerts[0].agent.id }}"
      comment: "Automated isolation due to malware detection"
      case_ids:
        - "{{ steps.create_case.output.id }}"
```

#### Update Alert Status

```yaml
- name: close_alert
  type: kibana.SetAlertsStatus
  with:
    status: closed
    reason: false_positive
    signal_ids:
      - "{{ event.alerts[0]._id }}"
```

---

## 5. Liquid Templating

Workflows use Liquid templating for dynamic content. Liquid provides filters to transform data and tags for control flow.

### Common Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `json` | Convert to JSON string | `{{ object \| json }}` |
| `json_parse` | Parse JSON string to object | `{{ json_string \| json_parse }}` |
| `size` | Get array/string length | `{{ items \| size }}` |
| `first` / `last` | Get first/last array item | `{{ items \| first }}` |
| `default` | Fallback value if nil | `{{ name \| default: "Unknown" }}` |
| `date` | Format date | `{{ "now" \| date: "%Y-%m-%d" }}` |
| `upcase` / `downcase` | Change case | `{{ text \| upcase }}` |
| `strip` | Remove whitespace | `{{ text \| strip }}` |
| `replace` | Replace substring | `{{ text \| replace: "old", "new" }}` |
| `truncate` | Shorten string | `{{ text \| truncate: 50 }}` |
| `slice` | Extract substring | `{{ hash \| slice: 0, 8 }}` |
| `split` | Split string to array | `{{ csv \| split: "," }}` |
| `join` | Join array to string | `{{ tags \| join: ", " }}` |
| `url_encode` | URL encoding | `{{ query \| url_encode }}` |
| `base64_encode` | Base64 encoding | `{{ text \| base64_encode }}` |

### Array Manipulation Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `map` | Extract property from array | `{{ users \| map: "name" }}` |
| `where` | Filter by property value | `{{ items \| where: "status", "active" }}` |
| `where_exp` | Filter with expression | `{{ items \| where_exp: "item.price > 100" }}` |
| `find` | Find first matching item | `{{ products \| find: "type", "book" }}` |
| `has` | Check if any item matches | `{{ products \| has: "category", "electronics" }}` |
| `reject_exp` | Remove matching items | `{{ products \| reject_exp: "item.stock == 0" }}` |
| `sort` | Sort by property | `{{ products \| sort: "name" }}` |
| `uniq` | Get unique values | `{{ items \| uniq }}` |
| `concat` | Concatenate arrays | `{{ array1 \| concat: array2 }}` |

### Working with Dates

Use the date filter with the special "now" string to get current time:

```yaml
# Current date in various formats
{{ "now" | date: "%Y-%m-%d" }}           # 2025-01-15
{{ "now" | date: "%Y-%m-%dT%H:%M:%SZ" }} # ISO format
{{ "now" | date: "%s" }}                 # Unix timestamp
```

### String Operations

```yaml
# Format message with data
message: "Alert: {{ event.rule.name | upcase }} on {{ event.host.name }}"

# Build URL with encoding
url: "https://api.example.com/search?q={{ query | url_encode }}"

# Extract substring (first 8 chars of hash)
short_hash: "{{ file.hash.sha256 | slice: 0, 8 }}"

# Default values for missing data
user: "{{ event.user.name | default: 'unknown' }}"
```

### Array Operations

```yaml
# Filter products where price > 100
{{ products | where_exp: "item.price > 100" }}

# Get all usernames from a list of users
{{ users | map: "username" | join: ", " }}

# Check if any alert is critical
{{ event.alerts | has: "severity", "critical" }}

# Sort alerts by timestamp
{{ event.alerts | sort: "@timestamp" }}
```

---

## 6. Control Flow

### Conditional Logic with Liquid Tags

Use Liquid tags for conditional content:

```yaml
message: |
  {%- if steps.search.output.hits.total > 0 -%}
  Found {{ steps.search.output.hits.total }} results
  {%- else -%}
  No results found
  {%- endif -%}
```

#### Case Statements

```yaml
message: |
  {%- assign severity = event.alerts[0].severity -%}
  {%- case severity -%}
    {%- when "critical" -%}
    🔴 CRITICAL: Immediate action required
    {%- when "high" -%}
    🟠 HIGH: Investigate promptly
    {%- when "medium" -%}
    🟡 MEDIUM: Review when possible
    {%- else -%}
    🟢 LOW: Normal priority
  {%- endcase -%}
```

#### Loops

```yaml
message: |
  {%- for alert in event.alerts -%}
  - {{ alert.rule.name }}: {{ alert.severity }}
  {%- endfor -%}
```

### Conditional Step Execution

Use the "if" step type to branch based on conditions:

```yaml
- name: check_severity
  type: if
  condition: "${{ steps.vt_check.output.data.stats.malicious > 10 }}"
  steps:
    - name: isolate_host
      type: kibana.request
      with:
        method: POST
        path: /api/endpoint/action/isolate
        body:
          endpoint_ids:
            - "{{ event.alerts[0].agent.id }}"
  else:
    - name: log_benign
      type: console
      with:
        message: "File appears benign, no action taken"
```

### Loops with Foreach

Iterate over arrays with foreach:

```yaml
- name: process_alerts
  type: foreach
  foreach: event.alerts
  steps:
    - name: log_alert
      type: console
      with:
        message: "Processing: {{ foreach.item['kibana.alert.rule.name'] }}"
    
    - name: create_case
      type: kibana.createCaseDefaultSpace
      with:
        title: "{{ foreach.item['kibana.alert.rule.name'] }}"
```

Inside a foreach block, access the current item with `{{ foreach.item }}`.

---

## 7. Error Handling

### Retry on Failure

Configure retry behavior for steps that might fail:

```yaml
- name: call_external_api
  type: http
  with:
    url: "https://api.example.com/data"
    method: GET
  on-failure:
    retry:
      max-attempts: 3
      delay: 5s
```

### Continue on Failure

Allow the workflow to proceed even if a step fails:

```yaml
- name: optional_enrichment
  type: http
  with:
    url: "{{ consts.enrichment_api }}"
    method: GET
  on-failure:
    retry:
      max-attempts: 2
      delay: 2s
    continue: true   # Proceed even on failure
```

### Timeouts

Set timeouts on long-running steps:

```yaml
- name: ai_analysis
  type: ai.agent
  with:
    agent_id: threat-analyst
    message: "Analyze this threat..."
  timeout: 10m
```

---

## 8. Real-World Examples

### Example 1: Daily Security Summary

Run an ES|QL query daily and send results to Slack:

```yaml
name: Daily Security Summary
description: Send daily alert summary to Slack

triggers:
  - type: scheduled
    with:
      every: "1d"

consts:
  slack_webhook: "https://hooks.slack.com/..."

steps:
  - name: query_alerts
    type: elasticsearch.esql.query
    with:
      format: json
      query: |
        FROM .alerts-security.alerts-default
        | WHERE @timestamp > NOW() - 24 hours
        | STATS alert_count = COUNT(*) BY host.name
        | SORT alert_count DESC
        | LIMIT 10

  - name: notify_slack
    type: http
    with:
      url: "{{ consts.slack_webhook }}"
      method: POST
      body:
        text: "🔔 Daily Summary: {{ steps.query_alerts.output.values | size }} hosts with alerts"
```

### Example 2: VirusTotal Hash Triage

Check file hashes against VirusTotal and take action:

```yaml
name: VT Hash Triage
description: Check file hash and respond based on results

triggers:
  - type: alert

consts:
  vt_api_key: "YOUR-API-KEY"

steps:
  - name: check_hash
    type: http
    with:
      url: "https://www.virustotal.com/api/v3/files/{{ event.alerts[0].file.hash.sha256 }}"
      method: GET
      headers:
        x-apikey: "{{ consts.vt_api_key }}"
      timeout: 30s

  - name: evaluate_result
    type: if
    condition: "${{ steps.check_hash.output.data.data.attributes.last_analysis_stats.malicious > 5 }}"
    steps:
      - name: create_case
        type: kibana.createCaseDefaultSpace
        with:
          owner: securitySolution
          title: "Malware: {{ event.alerts[0].file.hash.sha256 | slice: 0, 16 }}..."
          severity: high
      - name: isolate
        type: kibana.request
        with:
          method: POST
          path: /api/endpoint/action/isolate
          body:
            endpoint_ids:
              - "{{ event.alerts[0].agent.id }}"
    else:
      - name: close_fp
        type: kibana.SetAlertsStatus
        with:
          status: closed
          reason: false_positive
          signal_ids:
            - "{{ event.alerts[0]._id }}"
```

### Example 3: AI-Powered Root Cause Analysis

Use an AI agent to analyze alerts and create documented cases:

```yaml
name: AI Root Cause Analysis
description: AI-powered alert analysis

triggers:
  - type: alert

steps:
  - name: ai_analysis
    type: kibana.request
    with:
      method: POST
      path: /api/agent_builder/converse
      headers:
        kbn-xsrf: "true"
      body:
        agent_id: sre-agent
        input: |
          Investigate this alert and provide root cause analysis:
          {{ event | json }}
    timeout: 10m

  - name: create_case
    type: kibana.createCaseDefaultSpace
    with:
      owner: observability
      title: "RCA: {{ event.alerts[0]['kibana.alert.rule.name'] }}"
      description: "{{ steps.ai_analysis.output.response.message }}"
```

---

## 9. Quick Reference

### Step Types

| Type | Purpose |
|------|---------|
| `console` | Log messages to execution output |
| `http` | Make HTTP requests to external APIs |
| `wait` | Pause execution for a duration |
| `data.set` | Store computed values for later steps |
| `ai.agent` | Invoke AI agents |
| `if` | Conditional branching |
| `foreach` | Loop over arrays |
| `elasticsearch.request` | Raw Elasticsearch API calls |
| `elasticsearch.esql.query` | Run ES|QL queries |
| `elasticsearch.search` | Search queries with Query DSL |
| `kibana.request` | Raw Kibana API calls |
| `kibana.createCaseDefaultSpace` | Create security/observability cases |
| `kibana.SetAlertsStatus` | Update alert status |

### Trigger Types

| Type | When It Runs | Syntax |
|------|--------------|--------|
| `manual` | User-initiated from UI or API | `type: manual` |
| `alert` | When alerts fire | `type: alert` |
| `scheduled` | On a schedule | `type: scheduled` with `every: "6h"` |

### Context Variables

| Variable | Description |
|----------|-------------|
| `inputs.*` | User-provided input values |
| `consts.*` | Workflow constants |
| `steps.<n>.output` | Output from a previous step |
| `event.alerts[]` | Alert data (alert triggers only) |
| `event.rule.*` | Rule metadata (alert triggers only) |
| `execution.id` | Current execution ID |
| `execution.startedAt` | Execution start timestamp |
| `workflow.id` | Workflow ID |
| `kibanaUrl` | Kibana base URL |
| `foreach.item` | Current item in foreach loop |

### Common Kibana API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/cases` | Create and manage cases |
| `/api/cases/{id}/comments` | Add case comments |
| `/api/endpoint/action/isolate` | Isolate endpoints |
| `/api/endpoint/action/execute` | Run commands on endpoints |
| `/api/agent_builder/converse` | Invoke AI agents |

---

## 10. Importing Workflows

### Kibana UI

1. Open Kibana → Management → Workflows
2. Click "Create workflow"
3. Paste YAML content
4. Update constants for your environment
5. Save and test

### API Import

Import a single workflow via the API:

```bash
curl -X POST "https://KIBANA_URL/api/workflows" \
  -H "kbn-xsrf: true" \
  -H "x-elastic-internal-origin: Kibana" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d '{"yaml": "WORKFLOW_YAML_CONTENT"}'
```

### Bulk Import

Import multiple workflows from a directory:

```bash
for file in workflows/**/*.yaml; do
  echo "Importing: $file"
  cat "$file" | jq -Rs '{yaml: .}' | \
    curl -s -X POST "https://KIBANA_URL/api/workflows" \
      -H "kbn-xsrf: true" \
      -H "x-elastic-internal-origin: Kibana" \
      -H "Content-Type: application/json" \
      -H "Authorization: ApiKey API_KEY" \
      -d @-
done
```

### Community Workflows

Elastic maintains a public repository of workflow examples:

*https://github.com/elastic/workflows*

This repository contains 57+ workflows covering security, observability, search, and integrations with external systems like Splunk, Slack, Jenkins, JIRA, and more.

---

*End of Document*