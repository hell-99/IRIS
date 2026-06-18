# IRIS — Falcon QL Threat Hunting Queries

Behavioral threat hunting queries for CrowdStrike Falcon LogScale.
Run these in the `iris-alerts` repository against events ingested by `logscale_sink.py`.

All queries target the structured fields emitted by the IRIS integration:
`source`, `event_type`, `ttp_id`, `kc_stage`, `kc_phase`, `severity`,
`risk_score`, `agent_id`, `agent_role`, `tool_name`, `tool_args`, `time_delta_ms`

---

## 1. High-Risk Agent Activity (Risk ≥ 85)

Surfaces any agent whose actions crossed the critical risk threshold.
First-pass triage: use this to find sessions that need deeper review.

```
source = "iris"
| risk_score >= 85
| groupBy([agent_id, agent_role, session_id], function=[
    count(as=total_events),
    max(risk_score, as=peak_risk),
    collect(tool_name, as=tools_used),
    collect(ttp_id, as=ttps_observed)
  ])
| sort(peak_risk, order=desc)
```

---

## 2. Kill Chain Progression — Campaign Tracker

Detects multi-stage attacks where a single agent (or colluding agents)
advances through sequential kill chain stages within a session.
Stage jumps of ≥ 3 in a short window indicate rapid campaign escalation.

```
source = "iris"
| kc_stage > 0
| groupBy([session_id], function=[
    min(kc_stage, as=earliest_stage),
    max(kc_stage, as=latest_stage),
    count(as=events),
    collect(kc_phase, limit=10, as=stages_seen),
    max(risk_score, as=peak_risk)
  ])
| stage_spread := latest_stage - earliest_stage
| stage_spread >= 3
| sort(stage_spread, order=desc)
| rename([[session_id, Session], [stage_spread, StageSpread],
          [stages_seen, KillChainPath], [peak_risk, PeakRisk]])
```

---

## 3. Cross-Agent Collusion Detections

All confirmed collusion events — the IRIS novel detection capability.
Each event represents two agents coordinating an attack across separate sessions.

```
source = "iris"
  event_type = "collusion_detection"
| groupBy([pattern_name, ttp_id, kc_phase], function=[
    count(as=incidents),
    max(time_delta_ms, as=max_coordination_window_ms),
    avg(time_delta_ms, as=avg_coordination_window_ms),
    collect(agent_1_role, as=initiator_roles),
    collect(agent_2_role, as=executor_roles)
  ])
| sort(incidents, order=desc)
```

---

## 4. Exfiltration Pathway — Actions on Objectives (Stage 7)

Hunts for agents that reached the final kill chain stage.
Stage 7 = active data exfiltration or objective completion.
Correlate `tool_args` to identify what data was targeted.

```
source = "iris"
| kc_stage = 7
| kc_phase = "Actions on Objectives"
| table([timestamp, agent_id, agent_role, tool_name, tool_args,
         ttp_id, risk_score, session_id])
| sort(timestamp, order=desc)
```

---

## 5. Prompt Injection Attempts by TTP

Counts injection attempts grouped by MITRE ATLAS technique.
Useful for understanding the attack surface distribution.

```
source = "iris"
| ttp_id != ""
| label = "malicious" OR risk_score >= 65
| groupBy([ttp_id, ttp_name, kc_phase], function=[
    count(as=detections),
    avg(risk_score, as=avg_risk),
    max(risk_score, as=max_risk),
    count(allowed=false, as=blocked)
  ])
| block_rate := (blocked / detections) * 100
| sort(detections, order=desc)
```

---

## 6. Behavioral Drift — Agents Deviating from Baseline

Flags agents whose recent tool call mix diverges from their established pattern.
Sustained anomalous behavior is a stronger signal than a single high-risk event.

```
source = "iris"
  event_type = "tool_call"
| timeChart(span=5m, function=count(), by=[agent_role, tool_name])
| agent_role = "analyst"
| tool_name in ["execute_command", "modify_permissions", "call_api"]
```

---

## 7. Blocked vs Allowed — Policy Enforcement Gap

Shows which high-risk tool calls IRIS allowed despite elevated risk scores.
A large allowed count at high risk indicates policy needs tightening.

```
source = "iris"
  event_type = "tool_call"
| risk_score >= 65
| groupBy([tool_name, allowed, severity], function=[
    count(as=calls),
    avg(risk_score, as=avg_risk)
  ])
| sort([severity, calls], order=desc)
```

---

## 8. Real-Time Alert Rate (Last 15 Minutes)

Live SOC dashboard widget. Tracks IRIS alert volume per minute.
A sudden spike indicates an active campaign or new attack vector.

```
source = "iris"
| severity in ["HIGH", "CRITICAL"]
| timechart(span=1m, function=count(), by=severity)
```

---

## 9. Session Risk Timeline — Full Attack Reconstruction

Replays every event in a specific session in chronological order.
Use this after identifying a suspect session from queries 1 or 2.
Replace `<SESSION_ID>` with the actual session identifier.

```
source = "iris"
| session_id = "<SESSION_ID>"
| sort(timestamp, order=asc)
| table([timestamp, event_type, tool_name, tool_args,
         risk_score, allowed, ttp_id, kc_stage, kc_phase,
         agent_id, agent_role, latency_ms])
```

---

## 10. Coordination Speed — Sub-Second Collusion Window

Detects near-simultaneous cross-agent coordination (< 500 ms apart).
Attacks with sub-second timing suggest automated/scripted coordination
rather than coincidental behavior — highest confidence collusion signal.

```
source = "iris"
  event_type = "collusion_detection"
| time_delta_ms < 500
| groupBy([pattern_name, ttp_id], function=[
    count(as=fast_colluisions),
    min(time_delta_ms, as=fastest_ms),
    collect(agent_1_id, as=initiators)
  ])
| sort(fast_colluisions, order=desc)
```
