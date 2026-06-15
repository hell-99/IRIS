"""
Garak-IRIS Detection Efficacy Report
=====================================
Generates a colored terminal scorecard + JSON report from red team run results.
"""
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    _RICH = True
except ImportError:
    _RICH = False

KILL_CHAIN_STAGES = {
    1: "Reconnaissance",
    2: "Weaponization",
    3: "Delivery",
    4: "Exploitation",
    5: "Installation",
    6: "Command & Control",
    7: "Actions on Objectives",
}

CATEGORY_GARAK_REF = {
    "PROMPT_INJECTION":    "garak.probes.promptinject.*",
    "JAILBREAK":           "garak.probes.jailbreak.{Dan,Aim}",
    "PRIVILEGE_ESCALATION":"garak.probes.knownbadsignatures.*",
    "DATA_EXFILTRATION":   "garak.probes.continuation.*",
    "ENCODING_ATTACK":     "garak.probes.encoding.{InjectBase64,InjectROT13}",
}


def generate(results: list, output_dir: str = "data/red_team") -> dict:
    """Build report dict, print terminal output, save JSON."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    total      = len(results)
    detected   = sum(1 for r in results if r.get("detected"))
    bypassed   = total - detected
    rate       = detected / total * 100 if total else 0

    # Per-category breakdown
    by_cat = defaultdict(lambda: {"total": 0, "detected": 0, "probes": []})
    for r in results:
        cat = r["category"]
        by_cat[cat]["total"]   += 1
        by_cat[cat]["detected"] += 1 if r.get("detected") else 0
        by_cat[cat]["probes"].append(r)

    # Kill chain stage distribution
    kc_stages = defaultdict(int)
    for r in results:
        if r.get("detected"):
            kc_stages[r["kill_chain_stage"]] += 1

    # TTP breakdown
    ttp_counts = defaultdict(int)
    for r in results:
        if r.get("ttp_mapped"):
            ttp_counts[r["ttp_mapped"]] += 1

    # Missed probes (bypassed IRIS)
    missed = [r for r in results if not r.get("detected")]

    report = {
        "generated_at":    datetime.utcnow().isoformat(),
        "mode":            results[0]["mode"] if results else "simulation",
        "summary": {
            "total_probes":   total,
            "detected":       detected,
            "bypassed":       bypassed,
            "detection_rate": round(rate, 1),
        },
        "by_category":     {
            cat: {
                "total":          v["total"],
                "detected":       v["detected"],
                "detection_rate": round(v["detected"] / v["total"] * 100, 1) if v["total"] else 0,
                "garak_ref":      CATEGORY_GARAK_REF.get(cat, ""),
            }
            for cat, v in sorted(by_cat.items())
        },
        "kill_chain_coverage": {
            KILL_CHAIN_STAGES[s]: count
            for s, count in sorted(kc_stages.items())
        },
        "ttp_detections": dict(ttp_counts),
        "missed_probes":  [
            {"id": r["probe_id"], "category": r["category"],
             "description": r["description"], "garak_probe": r["garak_probe"]}
            for r in missed
        ],
        "all_results":    results,
    }

    # Save JSON
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"garak_iris_report_{ts}.json"
    path.write_text(json.dumps(report, indent=2))

    _print_report(report, by_cat, missed, rate, path)
    return report


def _print_report(report, by_cat, missed, rate, saved_path):
    if _RICH:
        _print_rich(report, by_cat, missed, rate, saved_path)
    else:
        _print_plain(report, by_cat, missed, rate, saved_path)


def _print_rich(report, by_cat, missed, rate, saved_path):
    console = Console()
    summary = report["summary"]

    rate_color = "green" if rate >= 80 else "yellow" if rate >= 60 else "red"

    console.print()
    console.print(Panel(
        f"[bold cyan]Garak Red Team  ×  IRIS Detection Efficacy[/bold cyan]\n"
        f"[dim]Mode: {report['mode']} | Generated: {report['generated_at'][:19]} UTC[/dim]",
        border_style="cyan",
    ))

    # Summary bar
    console.print(f"\n[bold]Overall Detection Rate:  "
                  f"[{rate_color}]{rate:.1f}%[/{rate_color}]  "
                  f"({summary['detected']}/{summary['total_probes']} probes)[/bold]")
    bar_filled  = int(rate / 5)
    bar_empty   = 20 - bar_filled
    bar = f"[{rate_color}]{'█' * bar_filled}[/{rate_color}][dim]{'░' * bar_empty}[/dim]"
    console.print(f"  {bar}  Bypassed: [red]{summary['bypassed']}[/red]\n")

    # Per-category table
    tbl = Table(title="Detection by Category", border_style="dim")
    tbl.add_column("Category",     style="cyan",    width=24)
    tbl.add_column("Garak Probe",  style="dim",     width=38)
    tbl.add_column("Probes",       justify="right")
    tbl.add_column("Detected",     justify="right")
    tbl.add_column("Rate",         justify="right")
    tbl.add_column("Status",       justify="center")

    for cat in sorted(by_cat):
        v        = by_cat[cat]
        cat_rate = v["detected"] / v["total"] * 100 if v["total"] else 0
        color    = "green" if cat_rate >= 80 else "yellow" if cat_rate >= 50 else "red"
        status   = "✓" if cat_rate == 100 else ("~" if cat_rate >= 50 else "✗")
        tbl.add_row(
            cat,
            CATEGORY_GARAK_REF.get(cat, ""),
            str(v["total"]),
            str(v["detected"]),
            f"[{color}]{cat_rate:.0f}%[/{color}]",
            f"[{color}]{status}[/{color}]",
        )
    console.print(tbl)

    # Kill chain coverage
    if report["kill_chain_coverage"]:
        console.print("\n[bold]Kill Chain Stage Coverage (detections):[/bold]")
        for stage_name, count in report["kill_chain_coverage"].items():
            bar_len = min(count * 4, 30)
            console.print(f"  [cyan]{stage_name:<30}[/cyan] {'█' * bar_len} {count}")

    # TTP breakdown
    if report["ttp_detections"]:
        console.print("\n[bold]MITRE ATLAS TTP Detections:[/bold]")
        for ttp, count in sorted(report["ttp_detections"].items(),
                                  key=lambda x: -x[1]):
            console.print(f"  [yellow]{ttp:<30}[/yellow] {count} detections")

    # Missed probes
    if missed:
        console.print(f"\n[bold red]Missed Probes ({len(missed)}) — IRIS did not detect:[/bold red]")
        for r in missed:
            console.print(f"  [red]✗[/red] [{r['probe_id']}] {r['description']}")
            console.print(f"      Garak: [dim]{r['garak_probe']}[/dim]")
    else:
        console.print("\n[bold green]All probes detected — zero bypasses.[/bold green]")

    console.print(f"\n[dim]Report saved: {saved_path}[/dim]\n")


def _print_plain(report, by_cat, missed, rate, saved_path):
    sep = "=" * 65
    print(f"\n{sep}")
    print("  Garak Red Team  x  IRIS Detection Efficacy Report")
    print(f"  Mode: {report['mode']} | {report['generated_at'][:19]} UTC")
    print(sep)
    print(f"\n  Overall Detection Rate: {rate:.1f}%  "
          f"({report['summary']['detected']}/{report['summary']['total_probes']})\n")

    print(f"  {'Category':<24} {'Probes':>6} {'Detected':>8} {'Rate':>6}")
    print(f"  {'-'*24} {'-'*6} {'-'*8} {'-'*6}")
    for cat in sorted(by_cat):
        v = by_cat[cat]
        r2 = v["detected"] / v["total"] * 100 if v["total"] else 0
        print(f"  {cat:<24} {v['total']:>6} {v['detected']:>8} {r2:>5.0f}%")

    if missed:
        print(f"\n  MISSED ({len(missed)}):")
        for r in missed:
            print(f"    - [{r['probe_id']}] {r['description'][:55]}")

    print(f"\n  Report saved: {saved_path}\n")
    print(sep)
