---
name: comfyharden-audit
description: Use when running a ComfyHarden security audit of a ComfyUI instance and interpreting the result. Triggers when the user asks to scan, audit, or check the security of a ComfyUI deployment, or to read a ComfyHarden grade. ComfyHarden is read-only; it writes only a report. For fixing the findings, use the comfyharden-remediation skill.
---

# Running a ComfyHarden audit and reading the result

ComfyHarden is a read-only security scanner for ComfyUI. It never changes the
instance; it writes a report. Use this skill to run an audit and interpret it.
To act on the findings, switch to the comfyharden-remediation skill.

## Run the audit

```
comfyharden audit <path-to-comfyui-install> --out ./report
```

- Safe to run on a live instance; it only reads and writes the report to `--out`.
- Add `--url http://127.0.0.1:8188 --authorized` only to probe a running instance
  you are authorized to test. The probe is non-exploitative and defaults to
  localhost. Never point it at a target you do not own.
- It works offline. The threat feed is bundled.

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

## Decide the next step

- Capture a baseline with `comfyharden snapshot <path> --out ./baseline` before
  any change, so the fixes are reversible (see the comfyharden-restore skill).
- If the grade is C or worse, hand `report.json` and `FIXES.md` to a coding agent
  running the comfyharden-remediation skill, and have the operator supervise.
- Lead your summary to the operator with the grade and the one or two findings
  that matter most, not a wall of every finding.
- After fixes are applied, run `comfyharden verify <path> --against <report.json>`
  to confirm they landed, and `comfyharden diff --against ./baseline/snapshot.json
  <path>` to confirm nothing else drifted.
