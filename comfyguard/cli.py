"""ComfyGuard command-line interface.

Phase 1 implements `audit` (read-only). snapshot/diff/restore are specified in
docs/SNAPSHOT.md and are stubbed here until a later phase.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .data import PRODUCTION_WARNING

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _banner(text, stream=sys.stderr):
    line = "=" * 72
    print(line, file=stream)
    for ln in text.splitlines():
        print(ln, file=stream)
    print(line, file=stream)


def cmd_audit(args) -> int:
    from . import collectors, report as report_mod
    from .checks import run_checks

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 3
    root = root.resolve()

    started = time.time()
    facts = collectors.collect(root, url=args.url, authorized=args.authorized,
                               launch_file=args.launch_file, launch_dir=args.launch_dir)
    if not facts.get("is_comfyui"):
        print(f"warning: {root} does not look like a ComfyUI install "
              "(no main.py/comfy/custom_nodes). Scanning anyway.", file=sys.stderr)
    if args.url and not args.authorized:
        print("note: --url was given without --authorized, so the network probe was skipped. "
              "Only probe instances you are authorized to test.", file=sys.stderr)

    findings = run_checks(facts, root)
    meta = {"started_at": _iso(started), "duration_seconds": round(time.time() - started, 2)}
    report = report_mod.build_report(facts, findings, meta)

    out_dir = Path(args.out).expanduser().resolve()
    report_mod.write_all(out_dir, report)

    _print_summary(report, out_dir)

    worst = max((SEV_ORDER.get(f["severity"], 0) for f in report["findings"]), default=0)
    fail_at = SEV_ORDER.get(args.fail_on, 4)
    if not args.no_fail and worst >= fail_at:
        return 2
    return 0


def _print_summary(report, out_dir):
    s = report["summary"]
    c = s["counts"]
    print()
    print(f"ComfyGuard {__version__} - audit complete (read-only, nothing was changed)")
    print(f"  Target : {report['scan']['target']['root']}")
    print(f"  Grade  : {s['grade']}   {s['grade_reason']}")
    print(f"  Counts : critical {c['critical']} | high {c['high']} | medium {c['medium']} | low {c['low']} | info {c['info']}")
    gate = "PASSED" if s["pre_exposure_gate_passed"] else f"FAILED ({len(s['blockers'])} blocker(s))"
    print(f"  Gate   : pre-exposure gate {gate}")
    print(f"  Report : {out_dir}/report.md, report.json, FIXES.md")
    top = [f for f in report["findings"] if f["severity"] in ("critical", "high")][:5]
    if top:
        print("  Top findings:")
        for f in top:
            owner = " [human decision]" if f.get("decision_owner") == "human" else ""
            print(f"    - [{f['severity']}] {f['check_id']} {f['title']}{owner}")
    print()
    _banner(PRODUCTION_WARNING)


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _not_yet(name):
    def run(args):
        print(f"`comfyguard {name}` is specified in docs/SNAPSHOT.md but not implemented in Phase 1.\n"
              f"Phase 1 ships `audit`. {name} is planned next.", file=sys.stderr)
        return 4
    return run


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # Distinct exit code for usage errors so they don't collide with audit's
        # "critical findings found" exit code (2).
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(64)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="comfyguard",
        description="Read-only security evaluation for ComfyUI. It scans an install and writes a "
                    "report plus an agent-ready FIXES.md. It changes nothing on your instance.")
    p.add_argument("--version", action="version", version=f"comfyguard {__version__}")
    sub = p.add_subparsers(dest="command", parser_class=_Parser)

    a = sub.add_parser("audit", help="Scan a ComfyUI install (read-only) and write a report.")
    a.add_argument("path", help="Path to the ComfyUI installation directory (or a portable root).")
    a.add_argument("--out", default="./comfyguard-report", help="Output directory for the report (default ./comfyguard-report).")
    a.add_argument("--url", default=None, help="Optional URL of the running instance for a safe network probe.")
    a.add_argument("--authorized", action="store_true",
                   help="Assert you are authorized to probe --url. Required for the network probe.")
    a.add_argument("--launch-file", default=None, help="Explicit launcher/unit file to read the bind flags from.")
    a.add_argument("--launch-dir", default=None, help="Extra directory to search for launcher files.")
    a.add_argument("--fail-on", default="critical", choices=list(SEV_ORDER),
                   help="Exit non-zero if a finding at or above this severity exists (default critical).")
    a.add_argument("--no-fail", action="store_true", help="Always exit 0 regardless of findings.")
    a.set_defaults(func=cmd_audit)

    for name in ("snapshot", "diff", "restore"):
        sp = sub.add_parser(name, help="(planned) see docs/SNAPSHOT.md")
        sp.add_argument("args", nargs="*", help="(accepted but ignored until implemented)")
        sp.set_defaults(func=_not_yet(name))

    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
