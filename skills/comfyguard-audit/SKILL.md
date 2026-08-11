---
name: comfyguard-audit
description: Use when running a ComfyGuard security audit of a ComfyUI instance and interpreting the result. Triggers when the user asks to scan, audit, or check the security of a ComfyUI deployment, or to read a ComfyGuard grade. ComfyGuard is read-only; it writes only a report. For fixing the findings, use the comfyguard-remediation skill.
---

# Running a ComfyGuard audit and reading the result

ComfyGuard is a read-only security scanner for ComfyUI. It never changes the
instance; it writes a report. Use this skill to run an audit and interpret it.
To act on the findings, switch to the comfyguard-remediation skill.

## Run the audit

```
comfyguard audit <path-to-comfyui-install> --out ./comfyguard-report
```

- Safe to run on a live instance; it only reads and writes three files to `--out`:
  `report.json` (structured, the source of truth), `report.md` (human summary),
  and `FIXES.md` (the agent-actionable plan). Default `--out` is
  `./comfyguard-report`.
- It works offline; the threat feed is bundled. No third-party dependencies.
- Add `--url http://127.0.0.1:8188 --authorized` only to probe a running instance
  you are authorized to test. The probe is read-only and non-exploitative. Never
  point it at a target you do not own.
- Exit code is `2` when a finding at or above `--fail-on` (default `critical`)
  exists, useful in CI; `0` otherwise.

## Read the grade

`report.md` leads with a single grade, A to F, and names the findings that set it.

- **F**: at least one high-confidence critical finding (for example, reachable
  without authentication, a known-malicious node present, or an unauthenticated
  RCE version). One is enough. Do not expose or keep exposing this instance.
- **D**: a lower-confidence critical, or several high findings.
- **C**: at least one high finding.
- **B**: only medium findings.
- **A**: only low or info findings.

The grade is deterministic and explains itself. A clean grade means no known-bad
patterns, versions, or configurations were found. It does not prove the instance
is safe.

Also read two fields on each finding: `urgency` (`blocker` findings are the
pre-exposure gate and must be resolved before the instance is exposed) and
`decision_owner` (`human` means an operator must decide, not an agent). The
summary carries `pre_exposure_gate_passed`.

## Decide the next step

> **Warning:** the target is likely a production instance. Applying fixes can
> break running pipelines. ComfyGuard only reports; it is a starting point.

- Lead your summary to the operator with the grade, whether the pre-exposure gate
  passed, and the one or two findings that matter most, not a wall of every
  finding.
- Before any change, capture a plain backup and note the current git commit and
  node/pip versions as a rollback point.
- If the grade is C or worse, hand `report.json` and `FIXES.md` to a coding agent
  running the comfyguard-remediation skill, with the operator supervising every
  `review-required` and `human-only` action.
- After fixes, re-run `comfyguard audit <path> --out ./after` and confirm the
  addressed findings are gone (match by `fingerprint`), the grade improved, and
  the workflows still run.
