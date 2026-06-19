"""
IRIS — NIST AI Risk Management Framework (AI RMF) Compliance Report

Maps IRIS detections and controls to the four core functions of the
NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE) and their subcategories.

Reference: NIST AI 100-1 (2023), https://airc.nist.gov/RMF/Overview

Usage:
    # Generate full compliance report
    python -m compliance.nist_ai_rmf

    # Programmatic use
    from compliance.nist_ai_rmf import NISTAIRMFReport
    report = NISTAIRMFReport()
    report.generate()
    report.print_summary()
    report.export_json("rmf_report.json")
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/logs/agentguard.db")

# ── NIST AI RMF subcategory definitions ───────────────────────────────────────
# Each entry maps an RMF subcategory to how IRIS satisfies it.
RMF_MAPPING = {
    "GOVERN": {
        "description": "Cultivate a culture of risk management through policies, accountability, and organizational practices.",
        "subcategories": {
            "GV-1.1": {
                "title": "Policies, processes, procedures established for AI risk management",
                "iris_control": "Declarative YAML policy engine (policy_engine.py) enforces role-based access, forbidden paths, and rate limits across all agent roles (admin/analyst/reader).",
                "iris_components": ["ml/policy_engine.py", "config.py → AGENT_ROLES"],
                "status": "IMPLEMENTED",
                "evidence": "AGENT_ROLES defines allowed_tools per role; forbidden_paths and forbidden_endpoints enforced at interception layer; RISK_THRESHOLD configurable via env var.",
            },
            "GV-1.2": {
                "title": "Accountability mechanisms established for AI risk outcomes",
                "iris_control": "SHA-256 tamper-evident audit ledger chains every tool call event. Each event has a prev_hash → curr_hash linkage making post-hoc modification detectable.",
                "iris_components": ["interceptor/core.py → _append_ledger()", "data/logs/agentguard.db → ledger table"],
                "status": "IMPLEMENTED",
                "evidence": "ledger table stores (event_id, prev_hash, curr_hash, timestamp) for every intercepted call. Tampering with any row breaks the hash chain.",
            },
            "GV-2.1": {
                "title": "Organizational teams aware of AI risks and roles",
                "iris_control": "Multi-tenant JWT authentication isolates data per user. Role-based dashboard access enforces least privilege on the monitoring plane itself.",
                "iris_components": ["auth/jwt.py", "auth/models.py"],
                "status": "IMPLEMENTED",
                "evidence": "JWT tokens scoped per user; demo account pre-loaded for evaluation; per-user DB isolation prevents cross-tenant data leakage.",
            },
            "GV-6.1": {
                "title": "Policies for AI transparency and explainability",
                "iris_control": "Every detection is explained: TTP ID, kill chain stage, divergence score, specific tool calls that triggered the flag, and description text rendered in the dashboard.",
                "iris_components": ["dashboard/app.py", "exports/sigma_exporter.py"],
                "status": "IMPLEMENTED",
                "evidence": "Collusion cards show pattern name, severity, TTP badge, kill chain stage, agent A + B tool calls, and time delta. No black-box decisions.",
            },
        },
    },

    "MAP": {
        "description": "Categorize AI risks in context — understand the system, its use cases, and the nature of potential harms.",
        "subcategories": {
            "MP-1.1": {
                "title": "Context established — intended purpose and known limitations documented",
                "iris_control": "IRIS operates in agentic LLM pipelines with access to files, databases, APIs, and system commands. Known limitations documented in README (static path detection, simulated training data, collusion false-positive rate in high-volume deployments).",
                "iris_components": ["README.md → Known Limitations"],
                "status": "IMPLEMENTED",
                "evidence": "README section explicitly documents: static sensitive path list, XGBoost trained on simulated data, collusion false-positive risk in busy deployments, intent analysis latency.",
            },
            "MP-2.3": {
                "title": "AI risks classified by type, likelihood, and impact",
                "iris_control": "MITRE ATLAS TTP taxonomy classifies every detected attack by type (prompt injection, exfiltration, lateral movement, privilege escalation, behavioral drift). Kill chain stage communicates attack progression severity.",
                "iris_components": ["config.py → MITRE_ATLAS_TTPS", "interceptor/core.py → _compute_risk()"],
                "status": "IMPLEMENTED",
                "evidence": "5 TTP categories mapped: AML.T0006 (Delivery/Stage 3), AML.T0043 (Exploitation/Stage 4), AML.T0025 (Actions on Objectives/Stage 7), AML.T0040 (Installation/Stage 5), AML.T0051 (C2/Stage 6).",
            },
            "MP-3.5": {
                "title": "Practices in place for AI supply chain risk",
                "iris_control": "LangChain callback integration (langchain_callback.py) monitors third-party agent frameworks. Behavioral fingerprinting (SHA-256) detects known-bad attack patterns regardless of which LLM or framework is used.",
                "iris_components": ["integrations/langchain_callback.py", "exports/fingerprint_engine.py"],
                "status": "IMPLEMENTED",
                "evidence": "IRISCallbackHandler wraps any LangChain agent with zero code changes. Fingerprints are framework-agnostic — same attack framing = same fingerprint ID.",
            },
            "MP-4.1": {
                "title": "Risks prioritized based on impact and likelihood",
                "iris_control": "Risk scoring (0–100) computed per tool call from tool sensitivity, permission violations, blocked count history, and session call volume. CRITICAL (≥85) / HIGH (≥65) / MEDIUM (≥40) / LOW thresholds drive response priority.",
                "iris_components": ["interceptor/core.py → _compute_risk()", "integrations/logscale_sink.py → _risk_to_severity()"],
                "status": "IMPLEMENTED",
                "evidence": "Risk score factors: base tool sensitivity (×5), +40 for unauthorized call, +30 for role violation, +10 per blocked call in session, +10 for high volume. Capped at 100.",
            },
        },
    },

    "MEASURE": {
        "description": "Analyze and assess AI risks using quantitative and qualitative methods.",
        "subcategories": {
            "MS-1.1": {
                "title": "Approaches for AI risk assessment defined and applied",
                "iris_control": "5-layer detection architecture: (1) rule engine + policy check, (2) XGBoost behavioral classifier, (3) Groq 70B intent-action divergence, (4) cross-agent collusion detector, (5) CUSUM drift detection. Each layer independently assesses risk.",
                "iris_components": ["interceptor/core.py", "ml/classifier.py", "ml/intent_detector.py", "ml/collusion_detector.py", "ml/drift_detector.py"],
                "status": "IMPLEMENTED",
                "evidence": "Layer 1–2 run in <1ms. Layer 3 (Groq 70B) adds 300–800ms — triggered on high-risk events. Layer 4 correlates across sessions with 120s time window. Layer 5 applies CUSUM from call 1.",
            },
            "MS-2.5": {
                "title": "AI system performance monitored against stated objectives",
                "iris_control": "Adversarial evaluation pipeline (adversarial_eval.py) measures precision, recall, F1 on 50 novel attack scenarios. Garak red-team integration validates 18 probe categories.",
                "iris_components": ["adversarial_eval.py", "red_team/runner.py", "red_team/report.py"],
                "status": "IMPLEMENTED",
                "evidence": "Locked metrics: 93.1% precision, 75.0% recall, 83.1% F1, 94.74% ML accuracy, 0.645ms avg latency. Garak: 18/18 probes detected, 0 bypasses across 5 attack categories.",
            },
            "MS-2.6": {
                "title": "AI risk metrics established and monitored over time",
                "iris_control": "CUSUM (Cumulative Sum Control Chart) monitors per-session risk drift in real-time. Uses first 40% of session as behavioral baseline; fires alarm before attack threshold reached.",
                "iris_components": ["ml/drift_detector.py"],
                "status": "IMPLEMENTED",
                "evidence": "CUSUM fires drift warning at call 17 (risk=23); rule engine fires at call 35 (risk=75). 9 behavioral drift warnings issued before any attack thresholds triggered in simulation.",
            },
            "MS-3.3": {
                "title": "Feedback from AI system operation incorporated into risk assessment",
                "iris_control": "Attack graph reconstruction (ml/attack_graph.py) generates kill chain graphs per flagged session, identifying which detection layer caught each call. This feeds back into model retraining and threshold calibration.",
                "iris_components": ["ml/attack_graph.py", "ml/comprehensive_metrics.py"],
                "status": "IMPLEMENTED",
                "evidence": "119 attack graphs reconstructed in simulation. Each graph maps tool calls to kill chain stages, identifies missed calls (known gap: single-file audit framing), and surfaces false positive patterns.",
            },
        },
    },

    "MANAGE": {
        "description": "Prioritize and implement responses to identified AI risks.",
        "subcategories": {
            "MG-1.1": {
                "title": "Risk response options identified and communicated",
                "iris_control": "Three response modes: (1) BLOCK — tool call denied at interception layer, (2) ALERT — Slack webhook notification, (3) LOG — structured event to SQLite + LogScale SIEM. Response escalates with risk score.",
                "iris_components": ["interceptor/core.py → intercept()", "integrations/langchain_callback.py → _trigger_alert()", "integrations/logscale_sink.py"],
                "status": "IMPLEMENTED",
                "evidence": "allowed=False blocks tool execution before it runs. Slack alerts fire at risk ≥ threshold. LogScale sink ships structured events for SIEM correlation. 90 calls blocked in simulation.",
            },
            "MG-2.2": {
                "title": "Mechanisms for AI incident response established",
                "iris_control": "Sigma rule export (sigma_exporter.py) generates SIEM-ready detection rules from IRIS findings. 26 Sigma rules exported covering all detected TTP categories — deployable to Splunk, Elastic, or any Sigma-compatible SIEM.",
                "iris_components": ["exports/sigma_exporter.py"],
                "status": "IMPLEMENTED",
                "evidence": "26 Sigma rules exported. Rules cover: prompt injection patterns, sensitive path access, API secrets endpoint access, cross-agent coordination timing, and permission escalation sequences.",
            },
            "MG-3.1": {
                "title": "Responses to identified AI risks prioritized and implemented",
                "iris_control": "Policy engine enforces real-time blocking decisions based on role × tool × risk score. Collusion detector fires CRITICAL alerts for cross-session coordination. Drift detector provides early warning before thresholds reached.",
                "iris_components": ["ml/policy_engine.py", "ml/collusion_detector.py", "ml/drift_detector.py"],
                "status": "IMPLEMENTED",
                "evidence": "14 collusion patterns detected and stored (8 CRITICAL, 6 HIGH). 38 suspicious intents flagged. 9 drift early warnings issued. All stored in collusion_detections and tool_calls tables.",
            },
            "MG-4.1": {
                "title": "Residual risks monitored and reported",
                "iris_control": "Known detection gaps documented: single-file reads with audit framing (50–62% detection rate), high-volume false-positive risk in collusion detector. Comprehensive metrics module tracks per-category performance.",
                "iris_components": ["ml/comprehensive_metrics.py", "README.md → Known Limitations"],
                "status": "PARTIAL",
                "evidence": "9 missed attacks documented (audit/training framing, single-path access). Gap acknowledged in README. Adaptive path detection identified as next improvement target.",
            },
        },
    },
}


# ── Report Generator ──────────────────────────────────────────────────────────

class NISTAIRMFReport:
    """
    Generates a NIST AI RMF compliance report for IRIS.

    Reads live metrics from the IRIS database and combines them with
    the static RMF mapping to produce a scored compliance summary.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path  = db_path
        self.metrics  = self._load_metrics()
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def _load_metrics(self) -> dict:
        """Pull live detection metrics from the IRIS database."""
        metrics = {
            "tool_calls": 0,
            "blocked_calls": 0,
            "sessions": 0,
            "collusion_detections": 0,
            "critical_collusions": 0,
            "suspicious_intents": 0,
            "avg_risk": 0.0,
            "max_risk": 0.0,
        }
        if not self.db_path.exists():
            return metrics

        con = sqlite3.connect(self.db_path)
        try:
            row = con.execute("""
                SELECT COUNT(*), SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END),
                       AVG(risk_score), MAX(risk_score),
                       SUM(CASE WHEN label='suspicious' THEN 1 ELSE 0 END)
                FROM tool_calls
            """).fetchone()
            if row and row[0]:
                metrics["tool_calls"]        = row[0] or 0
                metrics["blocked_calls"]     = row[1] or 0
                metrics["avg_risk"]          = round(row[2] or 0, 1)
                metrics["max_risk"]          = round(row[3] or 0, 1)
                metrics["suspicious_intents"]= row[4] or 0

            metrics["sessions"] = con.execute(
                "SELECT COUNT(*) FROM agent_sessions"
            ).fetchone()[0]

            try:
                row = con.execute("""
                    SELECT COUNT(*),
                           SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END)
                    FROM collusion_detections
                """).fetchone()
                metrics["collusion_detections"] = row[0] or 0
                metrics["critical_collusions"]  = row[1] or 0
            except sqlite3.OperationalError:
                pass
        finally:
            con.close()
        return metrics

    def generate(self) -> dict:
        """Return the full compliance report as a structured dict."""
        report = {
            "framework":    "NIST AI Risk Management Framework (AI RMF 1.0)",
            "system":       "IRIS — Identity Risk Intelligence System",
            "generated_at": self.generated_at,
            "live_metrics": self.metrics,
            "functions":    {},
            "summary":      {},
        }

        total = implemented = partial = 0

        for fn_name, fn_data in RMF_MAPPING.items():
            fn_result = {
                "description": fn_data["description"],
                "subcategories": {},
                "implemented": 0,
                "partial": 0,
                "total": 0,
            }

            for sub_id, sub in fn_data["subcategories"].items():
                fn_result["subcategories"][sub_id] = {
                    "title":           sub["title"],
                    "iris_control":    sub["iris_control"],
                    "iris_components": sub["iris_components"],
                    "status":          sub["status"],
                    "evidence":        sub["evidence"],
                }
                fn_result["total"] += 1
                total += 1
                if sub["status"] == "IMPLEMENTED":
                    fn_result["implemented"] += 1
                    implemented += 1
                elif sub["status"] == "PARTIAL":
                    fn_result["partial"] += 1
                    partial += 1

            fn_result["coverage_pct"] = round(
                (fn_result["implemented"] + fn_result["partial"] * 0.5)
                / fn_result["total"] * 100, 1
            )
            report["functions"][fn_name] = fn_result

        report["summary"] = {
            "total_subcategories":   total,
            "fully_implemented":     implemented,
            "partially_implemented": partial,
            "not_implemented":       total - implemented - partial,
            "overall_coverage_pct":  round(
                (implemented + partial * 0.5) / total * 100, 1
            ),
        }
        return report

    def print_summary(self):
        """Print a human-readable compliance summary to stdout."""
        report = self.generate()
        summary = report["summary"]
        metrics = report["live_metrics"]

        print("\n" + "=" * 70)
        print("  IRIS — NIST AI RMF Compliance Report")
        print(f"  Generated: {self.generated_at}")
        print("=" * 70)

        print(f"\nLive Metrics:")
        print(f"  Tool calls monitored : {metrics['tool_calls']}")
        print(f"  Calls blocked        : {metrics['blocked_calls']}")
        print(f"  Agent sessions       : {metrics['sessions']}")
        print(f"  Collusion detections : {metrics['collusion_detections']} ({metrics['critical_collusions']} CRITICAL)")
        print(f"  Suspicious intents   : {metrics['suspicious_intents']}")

        print(f"\nRMF Coverage:")
        for fn_name, fn_data in report["functions"].items():
            bar = "█" * int(fn_data["coverage_pct"] / 10)
            print(f"  {fn_name:<8} {bar:<10} {fn_data['coverage_pct']}%  "
                  f"({fn_data['implemented']}/{fn_data['total']} implemented)")

        print(f"\nOverall: {summary['overall_coverage_pct']}% coverage "
              f"({summary['fully_implemented']} implemented, "
              f"{summary['partially_implemented']} partial, "
              f"{summary['not_implemented']} gaps)")
        print("=" * 70 + "\n")

    def export_json(self, path: str = "nist_ai_rmf_report.json"):
        """Export the full report as JSON."""
        report = self.generate()
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[IRIS] NIST AI RMF report exported to {path}")
        return path

    def export_markdown(self, path: str = "nist_ai_rmf_report.md") -> str:
        """Export the full report as a Markdown document."""
        report = self.generate()
        lines  = [
            "# IRIS — NIST AI RMF Compliance Report",
            f"\n**Framework:** NIST AI Risk Management Framework (AI RMF 1.0)",
            f"**System:** IRIS — Identity Risk Intelligence System",
            f"**Generated:** {self.generated_at}",
            f"\n**Overall Coverage: {report['summary']['overall_coverage_pct']}%** "
            f"({report['summary']['fully_implemented']}/{report['summary']['total_subcategories']} subcategories fully implemented)\n",
            "---\n",
        ]

        for fn_name, fn_data in report["functions"].items():
            lines.append(f"## {fn_name} — {fn_data['description']}")
            lines.append(f"\n**Coverage: {fn_data['coverage_pct']}%**\n")

            for sub_id, sub in fn_data["subcategories"].items():
                status_icon = "✅" if sub["status"] == "IMPLEMENTED" else "⚠️"
                lines.append(f"### {status_icon} {sub_id}: {sub['title']}")
                lines.append(f"\n**IRIS Control:** {sub['iris_control']}\n")
                lines.append(f"**Components:** `{'`, `'.join(sub['iris_components'])}`\n")
                lines.append(f"**Evidence:** {sub['evidence']}\n")

        lines.append("---")
        lines.append("*Report generated by IRIS compliance module.*")

        content = "\n".join(lines)
        with open(path, "w") as f:
            f.write(content)
        print(f"[IRIS] NIST AI RMF report exported to {path}")
        return path


if __name__ == "__main__":
    report = NISTAIRMFReport()
    report.print_summary()
    report.export_json("nist_ai_rmf_report.json")
    report.export_markdown("nist_ai_rmf_report.md")
