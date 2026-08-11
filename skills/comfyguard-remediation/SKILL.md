---
name: comfyguard-remediation
description: Use when fixing a ComfyUI instance from a ComfyGuard security report. Triggers when a report.json or FIXES.md from ComfyGuard is present, or the user asks to remediate, harden, or fix ComfyGuard findings. Teaches an agent to read the report, apply fixes under gates, and verify them. ComfyGuard is read-only and never changes the instance; the agent does the fixing.
---

# Remediating a ComfyUI instance from a ComfyGuard report

ComfyGuard assessed a ComfyUI deployment and wrote a report. Your job is to fix
the findings safely. ComfyGuard changed nothing; every change is yours to make,
under the operator's supervision and the gates in the report.

> **Warning: this is a production instance.** Applying changes to a deployed
> ComfyUI can break running pipelines and workflows. ComfyGuard is a starting
> point, not a turnkey fix. Back up before every change, make one change at a
> time, test in a safe environment, and get operator confirmation for anything
> `review-required` or `human-only`. When in doubt, propose and stop.

## Inputs

- `report.json`: the source of truth. Structured findings plus a bill of
  materials. Read this, do not re-derive findings yourself.
- `FIXES.md`: the ordered, gated remediation plan rendered for you.
- `AGENTS.md`: the standing baseline for a secure ComfyUI instance.

If you only have one of `report.json` or `FIXES.md`, use it. They carry the same
findings; `report.json` is machine-precise, `FIXES.md` is ordered for action.

## Before you start: back up

Capture a rollback point before your first change. Use ComfyUI-Manager's snapshot
feature (`comfy node save-snapshot`, or the Manager UI) to capture node and package
state, note the core git commit (`git -C <path> rev-parse HEAD`), and copy any
config files you will edit. Keep the backup details in your notes so any change is
reversible. ComfyGuard does not manage snapshots itself.

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

1. Re-run `comfyguard audit <path> --out ./after` and compare against the prior
   `report.json`.
2. Confirm the finding you addressed is gone (match by `fingerprint`), the grade
   improved, and no new findings appeared.
3. Confirm the instance's pipelines still run before returning it to service.

The task is complete only when a re-scan confirms the addressed findings cleared,
nothing regressed, and the workflows still work. Reporting "fixed" without a
passing re-scan does not meet the contract. Leave `human-only` findings open with
a clear note of the decision the operator needs to make (whether the instance
should be reachable at all, whether a flagged node is needed enough to keep and
sandbox, whether an upgrade's compatibility risk is acceptable).
