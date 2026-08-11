"""Render the report artifacts: report.json, report.md, and FIXES.md."""

from __future__ import annotations

import json
from pathlib import Path

from . import RULESET_VERSION, SCHEMA_VERSION, __version__
from .data import PRODUCTION_WARNING
from .models import grade, grade_reason, sort_findings

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
# Phase ordering for FIXES.md.
PHASES = [
    ("Contain", {"ioc", "known-vulnerable-version"}, lambda f: f.remediation.get("class") == "quarantine" or f.category in ("ioc",)),
    ("Harden configuration", {"exposure", "authentication", "host"}, lambda f: f.category in ("exposure", "authentication", "host") and f.remediation.get("class") == "config"),
    ("Patch", set(), lambda f: f.remediation.get("class") == "upgrade"),
    ("Review node code and dependencies", {"custom-node-code", "dependency", "model-file"}, lambda f: f.category in ("custom-node-code", "dependency", "model-file")),
    ("Secrets", {"secret"}, lambda f: f.category == "secret"),
]


def build_report(facts, findings, meta) -> dict:
    findings = sort_findings(findings)
    g = grade(findings)
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    by_cat = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    blockers = [f.fingerprint for f in findings if f.urgency == "blocker"]
    core = facts.get("core", {})
    mgr = facts.get("manager", {})
    host = facts.get("host", {})
    launch = facts.get("launch", {})

    notes = []
    if host.get("perms_check_available") is False:
        notes.append("Directory-permission checks are unavailable on this platform (Windows) and were skipped.")
    if launch.get("source") is None:
        notes.append("No launch configuration or running process was detected; the bind address is undetermined (see EXP-000).")
    if facts.get("models", {}).get("capped"):
        notes.append("The model inventory hit the file cap and may be incomplete.")

    bom = {
        "nodes": [
            {"name": n["name"], "path": n["path"], "disabled": n.get("disabled"),
             "commit": n.get("commit"), "remote": n.get("remote"),
             "files_scanned": n.get("files_scanned"), "files_total": n.get("files_total")}
            for n in facts.get("nodes", [])
        ],
        "dependencies": {
            "declared_count": len(facts.get("deps", {}).get("declared", [])),
            "declared": [d["raw"] for d in facts.get("deps", {}).get("declared", [])],
        },
        "models": [
            {"path": m["path"], "ext": m["ext"], "size": m.get("size"), "pickle": m.get("pickle")}
            for m in facts.get("models", {}).get("files", [])
        ],
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "tool": {"name": "comfyguard", "version": __version__},
        "notices": {"production_warning": PRODUCTION_WARNING,
                    "read_only": "ComfyGuard changed nothing on this instance. Every fix is a proposal to review before applying."},
        "scan": {
            "started_at": meta.get("started_at"),
            "duration_seconds": meta.get("duration_seconds"),
            "notes": notes,
            "launch": {"source": launch.get("source"), "source_kind": launch.get("source_kind"),
                       "flags": launch.get("flags", {})},
            "target": {
                "root": facts.get("root"),
                "comfy_root": facts.get("comfy_root"),
                "is_comfyui": facts.get("is_comfyui"),
                "platform": facts.get("scanner", {}).get("platform"),
                "core_version": core.get("version"),
                "core_commit": core.get("commit"),
                "manager_present": mgr.get("present"),
                "manager_version": mgr.get("version"),
                "manager_security_level": mgr.get("security_level"),
                "custom_node_packs": len(facts.get("nodes", [])),
                "declared_dependencies": len(facts.get("deps", {}).get("declared", [])),
                "model_files": len(facts.get("models", {}).get("files", [])),
                "firewall_visible": bool((facts.get("firewall") or {}).get("available")),
                "url_probed": (facts.get("network") or {}).get("url"),
                "network_probe_authorized": bool(facts.get("network")),
            },
        },
        "summary": {
            "grade": g,
            "grade_reason": grade_reason(findings, g),
            "counts": counts,
            "by_category": by_cat,
            "blockers": blockers,
            "pre_exposure_gate_passed": len(blockers) == 0,
        },
        "bom": bom,
        "findings": [f.to_dict() for f in findings],
    }


def _warning_block() -> str:
    return "> **Important**\n" + "\n".join("> " + line for line in PRODUCTION_WARNING.splitlines()) + "\n"


def render_markdown(report: dict) -> str:
    s = report["summary"]
    t = report["scan"]["target"]
    lines = [f"# ComfyGuard report", ""]
    lines.append(_warning_block())
    lines.append(f"**Grade: {s['grade']}.** {s['grade_reason']}")
    lines.append("")
    gate = "PASSED" if s["pre_exposure_gate_passed"] else f"FAILED ({len(s['blockers'])} blocker finding(s))"
    lines.append(f"Pre-exposure gate: **{gate}**. "
                 "Blocker findings should be resolved before this instance is exposed to a network.")
    lines.append("")
    lines.append(f"Target: `{t['root']}` | core {t.get('core_version') or '?'} | "
                 f"Manager {'present' if t.get('manager_present') else 'absent'}"
                 f"{' ' + str(t.get('manager_version')) if t.get('manager_version') else ''}")
    c = s["counts"]
    lines.append("")
    lines.append("| Critical | High | Medium | Low | Info |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |")
    lines.append("")
    lch = report["scan"]["launch"]
    lines.append(f"Scanned {t.get('custom_node_packs', 0)} custom-node packs, "
                 f"{t.get('declared_dependencies', 0)} declared dependencies, "
                 f"{t.get('model_files', 0)} model files. "
                 f"Launch config: {lch.get('source') or 'not detected'}.")
    for note in report["scan"].get("notes", []):
        lines.append(f"- Note: {note}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report["findings"]:
        lines.append("No findings. Note: a clean result means no known-bad patterns were detected, not that the instance is safe.")
    for f in report["findings"]:
        loc = f["location"]
        where = loc.get("path", "")
        if loc.get("line"):
            where += f":{loc['line']}"
        badge = SEV_LABEL.get(f["severity"], f["severity"])
        owner = " · human decision" if f.get("decision_owner") == "human" else ""
        lines.append(f"### [{badge}] {f['check_id']} — {f['title']}")
        lines.append(f"`{f['urgency']}`{owner} · confidence {f['confidence']} · `{where}`")
        lines.append("")
        lines.append(f["description"])
        if f.get("impact"):
            lines.append(f"\n_Impact:_ {f['impact']}")
        if f.get("evidence"):
            lines.append(f"\n_Evidence:_ `{f['evidence']}`")
        rem = f.get("remediation", {})
        if rem:
            lines.append(f"\n_Proposed fix ({rem.get('gate', 'review-required')}):_ {rem.get('summary', '')}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_fixes(report: dict) -> str:
    lines = ["# FIXES.md — remediation plan for a coding agent", ""]
    lines.append(_warning_block())
    lines.append(f"Grade **{report['summary']['grade']}**. "
                 "ComfyGuard produced this plan and changed nothing. Work it under the gates: "
                 "`auto` may be applied directly, `review-required` needs operator confirmation, "
                 "`human-only` is never applied by an agent. Back up before any change "
                 "(ComfyUI-Manager's snapshot feature is a good rollback point), and "
                 "test in a safe environment first, because changes can break production pipelines.")
    lines.append("")
    findings = report["findings"]
    used = set()
    counter = [0]

    def emit(section, items):
        if not items:
            return
        lines.append(f"## {section}")
        lines.append("")
        for f in items:
            counter[0] += 1
            rem = f.get("remediation", {})
            loc = f["location"]
            where = loc.get("path", "")
            if loc.get("line"):
                where += f":{loc['line']}"
            gate = rem.get("gate", "review-required")
            owner = " HUMAN DECISION." if f.get("decision_owner") == "human" else ""
            lines.append(f"**act-{counter[0]:03d} ({gate}){owner} {f['title']}** "
                         f"[{f['check_id']}, {f['severity']}, {f['urgency']}] at `{where}`")
            lines.append(f"- Addresses: `{f['fingerprint']}`")
            lines.append(f"- What: {rem.get('summary', '')}")
            if rem.get("action"):
                lines.append(f"- How: {rem['action']}")
            if f.get("evidence"):
                lines.append(f"- Evidence: `{f['evidence']}`")
            if rem.get("rollback"):
                lines.append(f"- Rollback: {rem['rollback']}")
            lines.append("")

    for phase_name, _cats, pred in PHASES:
        phase_findings = [f for f in findings if id(f) not in used and pred_ok(f, pred)]
        for f in phase_findings:
            used.add(id(f))
        emit(phase_name, phase_findings)
    remaining = [f for f in findings if id(f) not in used]
    emit("Other findings to review", remaining)
    lines.append("## Verify")
    lines.append("")
    lines.append("After changes, re-run `comfyguard audit <path>` and confirm the addressed findings are gone and "
                 "the grade improved. Nothing is complete until a re-scan confirms it and the pipelines still run.")
    lines.append("")
    lines.append("## Decisions left to a person")
    lines.append("")
    humans = [f for f in findings if f.get("decision_owner") == "human"]
    if humans:
        for f in humans:
            lines.append(f"- {f['check_id']} — {f['title']}: {f.get('remediation', {}).get('summary', '')}")
    else:
        lines.append("- Whether this instance should be network-reachable at all.")
    return "\n".join(lines) + "\n"


def pred_ok(f_dict, pred):
    # PHASES predicates were written against Finding objects; adapt to dicts.
    class _F:
        def __init__(self, d):
            self.category = d.get("category")
            self.remediation = d.get("remediation", {})
    return pred(_F(f_dict))


def write_all(out_dir: Path, report: dict):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "FIXES.md").write_text(render_fixes(report), encoding="utf-8")
    return out_dir
