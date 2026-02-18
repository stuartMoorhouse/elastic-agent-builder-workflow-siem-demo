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

## Alternative Strategies (not yet tried)

1. **Restart `ElasticEndpoint.service`** — restart the actual endpoint sensor that owns the eBPF hooks and process tree cache. `sudo systemctl restart ElasticEndpoint.service` on the victim VM, wait for it to initialize, then test the attack. Estimated effort: 2 min. Likelihood: HIGH — this is the process that's stale and it hasn't been restarted yet.

2. **Restart both services on the victim** — `sudo systemctl restart ElasticEndpoint.service && sudo systemctl restart elastic-agent` to ensure both the sensor and orchestrator are in sync. Estimated effort: 3 min. Likelihood: HIGH.

3. **Full VM recreation via `reset-solr-red-vm.sh`** — the existing hard reset that taints and recreates the VM via Terraform. This is known to work (it was the previous approach). Estimated effort: 5 min. Likelihood: CERTAIN — but slow. Could be used as the fallback in the reset script if the soft approach fails.

4. **Investigate whether Elastic Defend behavioral protection is blocking/suppressing the event** — check endpoint logs on the VM (`/opt/Elastic/Endpoint/` logs) for evidence that the exploit is being detected and suppressed at the sensor level rather than reported as a process event. Estimated effort: 10 min. Likelihood: MEDIUM — would explain why the event is completely absent rather than just mis-enriched.

## Files Changed

| File | Status | Description |
|------|--------|-------------|
| `terraform/scripts/reset-demo.sh` | NEW | Soft reset script — kills processes, clears alerts/cases/suppression, verifies readiness. Includes detection of stale endpoint process tree (compares Java vs Agent start times via /proc). Does NOT restart Solr. |
| `DEBUGGING.md` | NEW | This debugging log |
