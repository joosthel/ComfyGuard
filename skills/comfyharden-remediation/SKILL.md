---
name: comfyharden-remediation
description: Use when fixing a ComfyUI instance from a ComfyHarden security report. Triggers when a report.json or FIXES.md from ComfyHarden is present, or the user asks to remediate, harden, or fix ComfyHarden findings. Teaches an agent to read the report, apply fixes under gates, and verify them. ComfyHarden is read-only and never changes the instance; the agent does the fixing.
---

# Remediating a ComfyUI instance from a ComfyHarden report

ComfyHarden assessed a ComfyUI deployment and wrote a report. Your job is to fix
the findings safely. ComfyHarden changed nothing; every change is yours to make,
under the operator's supervision and the gates in the report.

## Inputs

- `report.json`: the source of truth. Structured findings plus a bill of
  materials. Read this, do not re-derive findings yourself.
- `FIXES.md`: the ordered, gated remediation plan rendered for you.
- `AGENTS.md`: the standing baseline for a secure ComfyUI instance.

If you only have one of `report.json` or `FIXES.md`, use it. They carry the same
findings; `report.json` is machine-precise, `FIXES.md` is ordered for action.

## Before you start: snapshot for rollback

Take a baseline before your first change, so a fix that breaks the instance is
recoverable: `comfyharden snapshot <path> --out ./baseline` (read-only). If a
change breaks something, roll back with
`comfyharden restore ./baseline/snapshot.json --target <path>` and confirm with
`comfyharden diff --against ./baseline/snapshot.json <path>`. The
[comfyharden-restore](../comfyharden-restore/SKILL.md) skill covers this in full.

## How to read a finding

Each finding in `report.json` has:

- `check_id` and `title`: what was found.
- `severity` (critical/high/medium/low/info) and `confidence` (high/medium/low):
  act on high-severity, high-confidence findings first. Low confidence means
  verify the finding is real before acting.
- `location`: where it is. `kind` is `file`, `endpoint`, `config`, `process`,
  `container`, `dependency`, or `model`, with a `path` and optional line range.
- `evidence`: the matched value or snippet. For secrets this is redacted.
- `remediation`: `class` (config, upgrade, quarantine, secret, manual, context),
  `gate` (auto, review-required, human-only), a `summary`, an `action`, and a
  `rollback`.
- `fingerprint`: the stable id you use to confirm the finding cleared after a fix.

## Order of work

Follow the phase order in `FIXES.md`. It exists because doing things out of order
either misses the biggest risk or breaks the instance:

1. **Contain.** Quarantine known-malicious nodes and model files by moving them
   aside, never by deleting. If a known-malicious node is present, treat the host
   as possibly compromised and tell the operator.
2. **Harden configuration.** Bind to loopback, add an authenticating TLS proxy,
   remove permissive CORS, set the Manager security level to strong and disable
   runtime install flags, set `--disable-api-nodes` and `--disable-metadata` where
   appropriate. These are precise, reversible edits to launch scripts, systemd
   units, compose files, and `config.ini`.
3. **Patch.** Upgrade core, Manager, and vulnerable nodes to the fixed versions
   named in the finding. Run the instance's smoke-test workflows before returning
   it to service, because upgrades can change behavior.
4. **Secrets.** Move secrets out of the shared process environment into mounted
   files or a secrets manager. Do not rotate a live credential yourself.

## The gates (do not violate)

- `auto`: reversible, low-risk config edits with a clear rollback. Apply directly,
  then verify.
- `review-required`: apply only after the operator confirms.
- `human-only`: never apply. This always includes deleting a node or model,
  rotating a credential, redeploying or restarting a production service, and
  changing any system you were not authorized to touch.

## Non-negotiable rules

- Back up any file before you edit it. Note the backup path.
- Never delete a node or model. Quarantine by moving it aside so a false positive
  is recoverable and evidence is preserved.
- Never run a flagged node or load a flagged model to "confirm" it.
- Never print, move, or rotate a live secret. Flag it for the credential owner.
- One change at a time.

## Close the loop

After each change (or a small batch of related ones):

1. Run `comfyharden verify <path> --against <the prior report.json>`.
2. Confirm the finding you addressed cleared, matched by `fingerprint`.
3. Confirm no new findings appeared.

The task is complete only when the addressed findings clear on a `verify` run and
nothing regressed. Reporting "fixed" without a passing verify does not meet the
contract. Leave `human-only` findings open with a clear note of the decision the
operator needs to make (whether the instance should be reachable at all, whether a
flagged node is needed enough to keep and sandbox, whether an upgrade's
compatibility risk is acceptable).
