# Debugging Log — 2026-02-18 — Elastic Defend drops process events after Solr restart

## Objective
Create a fast "soft reset" script (`reset-demo.sh`) that resets the demo environment between runs without recreating VMs. After reset, running the attack should trigger the detection rule "Shell Spawned by Java Process" and fire an alert.

## What Works
- The reset script successfully: kills attacker Metasploit processes, kills victim reverse shells, deletes Elastic Security alerts, resets detection rule suppression (disable/re-enable), deletes Security cases, verifies agent health
- The attack script successfully spawns a reverse shell (confirmed via `ps` — shell PID with PPID=java)
- The detection rule is enabled and executing every 10s with "succeeded" status
- Process events ARE flowing from the host (hundreds per minute in `logs-endpoint.events.process-*`)
- The EQL query is correct: `process where event.type == "start" and host.os.type == "linux" and process.parent.name == "java" and process.name in ("sh", "bash", "dash", ...)`

## Approaches Tried

- **Attempt 1**: Reset script with `systemctl restart solr` to get a clean process tree.
  - Result: After reset + attack, zero alerts. Investigation showed zero `process.parent.name: "java"` events in ES despite shell running with parent=java on the host. All historical java-parent events referenced the OLD Java PID (9065 from boot), none from the new PID (14960 from restart).
  - Why it failed: Restarting Solr created a new Java PID that the Elastic Defend endpoint sensor couldn't track.

- **Attempt 2**: Removed `systemctl restart solr` from reset script, only kill reverse shell processes.
  - Result: Same — zero alerts after attack. The damage was already done by Attempt 1's Solr restart. The Java PID 14960 (from the Attempt 1 restart) persisted.
  - Why it failed: The stale endpoint state from Attempt 1 was permanent.

- **Attempt 3**: Restarted `elastic-agent` service (`systemctl restart elastic-agent`) to rebuild process tree.
  - Result: Agent restarted (new PID 16140 at 16:59), filebeat/osquery children restarted, but `elastic-endpoint` (PID 9847 from 08:39) was NOT restarted. Zero alerts after attack.
  - Why it failed: `ElasticEndpoint.service` is a SEPARATE systemd service from `elastic-agent.service`. Restarting the agent does not restart the endpoint sensor.

## Current Error State
The exploit spawns a reverse shell that is visible via `ps`:
```
PID=17067 PPID=14960 CMD=sh PARENT=java
```

But Elasticsearch has zero matching events:
```
# Search by parent name
logs-endpoint.events.process-* where process.parent.name=java AND @timestamp > now-15m → 0 hits

# Search by parent PID
logs-endpoint.events.process-* where process.parent.pid=14960 → 0 hits (all time)

# Search by child PID across ALL endpoint indices
logs-endpoint* where process.pid=17067 → 0 hits
```

The endpoint sensor process has been running since boot and was never restarted:
```
ElasticEndpoint.service  — PID 9847, started Wed Feb 18 08:39:41 2026 (boot)
elastic-agent.service    — PID 16140, started Wed Feb 18 16:59:03 2026 (restarted)
Java/Solr                — PID 14960, started Wed Feb 18 16:39:12 2026 (Solr restart)
```

## Root Cause

After Solr restarts (new Java PID), Elastic Defend's endpoint sensor fails to attribute
`process.parent.name: "java"` on shells spawned by the new Java process. The exact internal
mechanism is unclear — the eBPF hooks (`sched_process_fork`/`sched_process_exec`) should see
all process events system-wide, so the sensor should observe the new Java starting. The failure
likely involves the sensor's internal process table or `entity_id` ancestry tracking getting
into an inconsistent state during process replacement.

What is confirmed:
- `ElasticEndpoint.service` is a **separate** systemd service from `elastic-agent.service` —
  restarting the agent does NOT restart the endpoint sensor
  ([elastic-agent#2318](https://github.com/elastic/elastic-agent/issues/2318))
- Restarting `ElasticEndpoint.service` forces a clean re-initialization (including `/proc` re-scan)
  which fixes the problem

**Fix**: Restart `ElasticEndpoint.service` directly, then `elastic-agent` to keep them in sync.

## Fix Applied

Updated `reset-demo.sh` to restart `ElasticEndpoint.service` (then `elastic-agent`) when a stale
process tree is detected, and verify the endpoint sensor started after Java before proceeding.

## Files Changed

| File | Status | Description |
|------|--------|-------------|
| `terraform/scripts/reset-demo.sh` | NEW | Soft reset script — kills processes, clears alerts/cases/suppression, verifies readiness. Includes detection of stale endpoint process tree (compares Java vs Agent start times via /proc). Does NOT restart Solr. |
| `DEBUGGING.md` | NEW | This debugging log |
