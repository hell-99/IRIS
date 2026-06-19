# IRIS — STRIDE Threat Model

**System:** IRIS — Identity Risk Intelligence System  
**Methodology:** STRIDE (Microsoft Threat Modeling)  
**Scope:** IRIS monitoring infrastructure — the interceptor, detection engine, database, dashboard, and API  
**Date:** June 2026

> **Why threat-model the monitor?**  
> An adversary who can compromise the monitoring layer can blind the entire security stack. IRIS is a high-value target: subvert it, and every subsequent attack goes undetected. This document applies STRIDE to IRIS itself — not to the agents it monitors.

---

## System Components

```
┌─────────────────────────────────────────────────────────┐
│                    IRIS Architecture                     │
│                                                          │
│  LLM Agent  ──►  Interceptor  ──►  Detection Engine     │
│                      │               │                   │
│                      ▼               ▼                   │
│                  SQLite DB       Risk Scorer             │
│                      │               │                   │
│                      ▼               ▼                   │
│                  Audit Ledger    ML Classifier           │
│                                   Collusion Det.         │
│                                   Drift Detector         │
│                      │                                   │
│                      ▼                                   │
│              FastAPI :8000  ──►  Streamlit :8501         │
│                      │                                   │
│                      ▼                                   │
│              LogScale SIEM / Slack Webhook               │
└─────────────────────────────────────────────────────────┘
```

**Trust boundaries:**
- Agent ↔ Interceptor (partially trusted — agent may be compromised)
- Interceptor ↔ SQLite (trusted — same process)
- FastAPI ↔ Dashboard (authenticated via JWT)
- IRIS ↔ LogScale (network boundary — token-authenticated)

---

## STRIDE Analysis

### S — Spoofing

**Threat 1: Agent Identity Spoofing**  
An attacker controls an agent and submits tool call events to IRIS with a forged `agent_id` or `agent_role` (e.g., claiming `role=admin` to bypass analyst-level risk thresholds).

- **Impact:** High — forged admin role grants wider allowed_tools, suppressing risk score elevation
- **Likelihood:** Medium — requires access to the interceptor call interface
- **IRIS Mitigation:** `agent_id` is generated server-side per session (`langchain_{role}_{uuid}`). Role is bound at session creation from the callback handler constructor, not from agent self-reporting.
- **Residual Risk:** If an attacker can call `intercept()` directly with arbitrary parameters (e.g., via a compromised LangChain integration), role spoofing is possible.
- **Recommendation:** Add HMAC signing to `intercept()` call parameters; validate `agent_role` against an allowlist at the API boundary.

---

**Threat 2: Dashboard User Spoofing**  
An attacker forges or replays a JWT token to access another user's IRIS dashboard and detection data.

- **Impact:** High — exposes full session history, detection data, agent behavior logs
- **Likelihood:** Low — requires JWT secret compromise or token theft
- **IRIS Mitigation:** JWT tokens are signed with a server-side secret; per-user DB isolation means even a valid token only exposes that user's data.
- **Residual Risk:** Short token expiry not enforced in current implementation.
- **Recommendation:** Enforce JWT expiry (e.g., 8-hour TTL); add token revocation for logout.

---

### T — Tampering

**Threat 3: Audit Log Tampering**  
An attacker with database write access modifies `tool_calls` rows to erase evidence of malicious activity (e.g., change `label=malicious` to `label=benign`, delete blocked call records).

- **Impact:** Critical — destroys forensic evidence, breaks incident reconstruction
- **Likelihood:** Medium — SQLite file is writable by any process with filesystem access
- **IRIS Mitigation:** SHA-256 tamper-evident ledger (`ledger` table) chains every event. Each row stores `prev_hash` and `curr_hash` — modifying any `tool_calls` row without updating the ledger chain produces a detectable hash mismatch.
- **Residual Risk:** An attacker who can write to both `tool_calls` AND `ledger` can recompute a valid chain. The ledger provides detection, not prevention, against a sufficiently capable attacker.
- **Recommendation:** Export ledger hashes to an append-only external store (LogScale, S3 with object lock) immediately after each event. Out-of-band verification makes chain recomputation impractical.

---

**Threat 4: ML Model Poisoning**  
An attacker feeds carefully crafted tool call sequences to IRIS during a training window, causing the XGBoost classifier to learn that malicious patterns are benign.

- **Impact:** High — classifier silently mis-labels future attacks
- **Likelihood:** Low in current deployment (model is pre-trained on simulation data, not live data)
- **IRIS Mitigation:** XGBoost model is trained offline on labeled simulation data; live traffic does not retrain the model automatically. Layers 1 and 3 (rule engine + Groq 70B intent analysis) are not ML models and cannot be poisoned.
- **Residual Risk:** If continuous learning is added, poisoning becomes a real threat.
- **Recommendation:** If retraining is introduced, require human review of new training samples above a risk threshold; implement data provenance tracking.

---

### R — Repudiation

**Threat 5: Agent Denying Malicious Tool Calls**  
A compromised agent or its operator claims a malicious tool call was never made, or was made in error.

- **Impact:** Medium — undermines accountability, complicates incident response
- **Likelihood:** Medium — denial is a standard attacker tactic post-incident
- **IRIS Mitigation:** Every tool call is logged with UUID, timestamp, agent_id, tool_name, args, risk_score, and allowed status. SHA-256 ledger provides non-repudiation — the hash chain proves the event was logged at a specific point in time relative to surrounding events.
- **Residual Risk:** Ledger is currently local-only. A sufficiently privileged attacker could delete the entire database.
- **Recommendation:** Stream ledger hashes to LogScale or another append-only external system in real-time (already supported via `logscale_sink.py`).

---

**Threat 6: IRIS Operator Repudiation**  
An IRIS operator claims a detection was not generated, or that a block decision was never made, to avoid accountability for a missed attack.

- **Impact:** Low-Medium — relevant in regulated environments
- **Likelihood:** Low — primarily a compliance/audit concern
- **IRIS Mitigation:** Detection events are immutable once written (no UPDATE/DELETE in normal flow). Ledger provides cryptographic evidence of detection timing.
- **Recommendation:** Multi-party audit access to detection records (read-only role in dashboard) for compliance reviewers.

---

### I — Information Disclosure

**Threat 7: Exposing Detection Rules to Adversaries**  
An attacker who reads IRIS source code or the SQLite database learns exactly which tool call patterns, path names, and TTP signatures trigger detection — and crafts attacks that stay just below thresholds.

- **Impact:** High — enables targeted evasion of all detection layers
- **Likelihood:** Medium — IRIS is open-source; detection logic is publicly visible
- **IRIS Mitigation:** Layer 3 (Groq 70B intent-action divergence) does not use static rules — it reasons about expected vs. actual tool calls using the task description. This layer is not bypassable by knowing the rule list.
- **Residual Risk:** Layers 1 and 2 (rule engine, XGBoost features) are bypassable with knowledge of the source code.
- **Recommendation:** In production deployments, keep Layer 1 pattern lists configurable and secret (environment-injected, not hardcoded). Add decoy sensitive paths that trigger on access.

---

**Threat 8: JWT Secret Exposure via Environment Variables**  
The JWT signing secret, Groq API key, Slack webhook URL, and LogScale ingest token are loaded from environment variables. If `.env` is committed to git or logged, all secrets are exposed.

- **Impact:** Critical — JWT secret compromise allows forging any user token
- **Likelihood:** Low (with discipline) — `.env` is in `.gitignore`
- **IRIS Mitigation:** `.env` explicitly excluded from git. Secret loading via `os.getenv()` with no defaults for sensitive values.
- **Residual Risk:** Secrets may appear in process listings, container environment dumps, or CI/CD logs.
- **Recommendation:** Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) for production; rotate LogScale token and Slack webhook on any suspected exposure.

---

### D — Denial of Service

**Threat 9: Interceptor Flood Attack**  
A compromised agent generates thousands of tool calls per second, overwhelming the interceptor, saturating the SQLite write lock, and causing legitimate detections to be queued or dropped.

- **Impact:** High — monitoring blindness during an active attack
- **Likelihood:** Medium — a colluding agent pair could deliberately flood IRIS while a third agent executes the real attack
- **IRIS Mitigation:** Risk scoring includes a volume heuristic (`session_call_count * 0.5`, capped at +10). High call volume itself elevates risk score. Collusion detector runs on a 120-second sliding window, not per-call.
- **Residual Risk:** No explicit rate limiting or circuit breaker on the interceptor in current implementation.
- **Recommendation:** Add per-session rate limiting (e.g., max 100 calls/minute before automatic session suspension); use WAL mode for SQLite to reduce write contention under load.

---

**Threat 10: Groq API Rate Limiting**  
Layer 3 (intent-action divergence via Groq 70B) depends on an external API. An attacker who triggers many simultaneous high-risk events exhausts the Groq rate limit, disabling the deepest detection layer.

- **Impact:** Medium — Layers 1 and 2 still function; Layer 3 misses the hardest cases
- **Likelihood:** Low — Groq rate limits are generous; this requires coordinated triggering
- **IRIS Mitigation:** Layer 3 is only triggered when earlier layers surface suspicious activity. In a DoS scenario, volume itself elevates risk scores and may trigger blocks before Layer 3 is needed.
- **Recommendation:** Cache Layer 3 results for identical (task, tool_sequence) pairs; implement exponential backoff with Layer 1/2 fallback on Groq timeout.

---

### E — Elevation of Privilege

**Threat 11: Exploiting the FastAPI Backend**  
An unauthenticated attacker calls IRIS API endpoints directly (e.g., `GET /api/collusion`, `GET /api/sessions`) to read detection data without a valid JWT, or calls internal endpoints to inject false detections.

- **Impact:** High — exposes all detection data; false injection can trigger false alerts or suppress real ones
- **Likelihood:** Low — API runs on localhost:8000 in standard deployment
- **IRIS Mitigation:** All non-auth endpoints require a valid JWT (enforced via FastAPI dependency injection). Auth endpoints (`/auth/register`, `/auth/login`) are public but rate-limited by design.
- **Residual Risk:** If IRIS API is exposed beyond localhost (e.g., in a cloud deployment without a reverse proxy), authentication becomes the only barrier.
- **Recommendation:** Bind FastAPI to `127.0.0.1` in production unless explicitly proxied; add IP allowlist middleware for non-local deployments.

---

**Threat 12: IRIS Dashboard Privilege Escalation**  
An authenticated user with a low-privilege account modifies API requests to access another user's data or admin-level dashboard features.

- **Impact:** Medium — cross-tenant data leakage in multi-user deployments
- **Likelihood:** Low — per-user DB isolation separates data at the database level
- **IRIS Mitigation:** Per-user database isolation: each user account's detections are stored in a separate SQLite partition. A valid JWT for User A cannot access User B's data even if the API is called correctly.
- **Recommendation:** Add explicit ownership checks on every API response object as a defense-in-depth layer; log cross-user access attempts.

---

## Risk Summary

| ID | Threat | STRIDE | Severity | Status |
|----|--------|--------|----------|--------|
| T1 | Agent identity spoofing via forged role | S | HIGH | Partially mitigated |
| T2 | JWT token forgery/replay | S | HIGH | Mitigated |
| T3 | Audit log tampering | T | CRITICAL | Mitigated (ledger) |
| T4 | ML classifier poisoning | T | HIGH | Low risk (offline training) |
| T5 | Agent denying tool calls | R | MEDIUM | Mitigated (ledger) |
| T6 | Operator repudiation of detections | R | LOW | Mitigated |
| T7 | Detection rule exposure enabling evasion | I | HIGH | Partially mitigated (Layer 3) |
| T8 | Secret/JWT key exposure | I | CRITICAL | Mitigated (.gitignore) |
| T9 | Interceptor flood by compromised agent | D | HIGH | Partially mitigated |
| T10 | Groq API exhaustion | D | MEDIUM | Partially mitigated |
| T11 | FastAPI unauthorized access | E | HIGH | Mitigated (JWT) |
| T12 | Dashboard privilege escalation | E | MEDIUM | Mitigated (DB isolation) |

**Legend:** Mitigated = control fully addresses threat | Partially mitigated = control reduces but does not eliminate | Open = no current control

---

## Top Recommendations

1. **Export ledger hashes to append-only external store** (LogScale) — closes T3/T5 residual risk
2. **Add HMAC signing to interceptor call parameters** — closes T1 agent role spoofing
3. **Enforce JWT expiry + token revocation** — closes T2 residual risk
4. **Rate-limit per-session tool call volume** — closes T9 interceptor flood
5. **Keep Layer 1 pattern lists secret in production** — reduces T7 evasion risk

---

*Threat model authored using STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Reference: Microsoft Threat Modeling Tool, OWASP Threat Dragon.*
