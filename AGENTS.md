# AGENTS.md: securing a ComfyUI instance

This file gives an automated coding agent the basics of what a secure ComfyUI
deployment looks like and how to fix a specific one. It is the standing baseline.
For a specific instance, an operator runs `comfyharden audit`, and you work from
the `FIXES.md` it writes, which is tailored to that deployment. ComfyHarden itself
never changes anything; you do the fixing.

The detailed, step-by-step skill for consuming a report is in
[skills/comfyharden-remediation/SKILL.md](skills/comfyharden-remediation/SKILL.md).

## The security model in one line

ComfyUI trusts anyone who can reach its URL. On a network, security is the
operator's job, not the platform's. So the first question for any instance is
always: who can reach it, and is that intended?

## What "secure enough for production" means

An instance meets the baseline when all of these hold:

1. It is not directly reachable on a network. It binds to localhost, and any
   remote access goes through an authenticating, TLS-terminating reverse proxy or
   a VPN.
2. Every path in requires authentication. ComfyUI core has none, so this lives in
   the proxy or network layer. `--multi-user` is storage partitioning, not
   authentication.
3. ComfyUI core and ComfyUI-Manager are up to date, and Manager's security level
   is `strong` on any networked instance, with runtime pip and git installs off.
4. Custom nodes come from trusted sources, are reviewed before install, and none
   run code at import time or reach out to unexpected hosts.
5. Models are `safetensors` where possible. Pickle formats (`.ckpt`, `.pt`,
   `.bin`) from untrusted sources are treated as code, not data.
6. The process runs as a non-root, least-privilege user or container. No
   `--privileged`, no mounted Docker socket, no broad host bind-mounts.
7. Secrets are not in the process environment (every node can read it). Outbound
   egress is restricted by default.
8. The instance was assessed before exposure and is re-assessed on a schedule.

## The workflow

1. **Snapshot first.** Before changing anything, run
   `comfyharden snapshot <path> --out ./baseline` to capture a known-good rollback
   point. This is read-only. See the
   [comfyharden-restore](skills/comfyharden-restore/SKILL.md) skill.
2. **Read the report.** Load `report.json` (the source of truth) and `FIXES.md`
   (the ordered, gated plan). Do not re-derive findings yourself; act on the ones
   ComfyHarden found.
3. **Work the plan in order.** Contain first (quarantine known-malicious nodes and
   models), then configuration, then patches, then secrets.
4. **One change at a time.** Make a change, then run `comfyharden verify` and
   confirm the finding cleared by its fingerprint before moving on.
5. **Roll back if a change breaks the instance.** Use
   `comfyharden restore ./baseline/snapshot.json --target <path>` and confirm with
   `comfyharden diff --against ./baseline/snapshot.json <path>` (an empty diff
   means you are back to the baseline).
6. **Verify at the end.** The task is done when the addressed findings clear and
   nothing regressed.

`restore --apply` is the one ComfyHarden command that changes an instance, and it
is gated like any other change: confirm with the operator, and it never deletes
(it quarantines).

## Do

- Back up any file before editing it. Keep the backup path in your notes.
- Prefer the smallest reversible change that resolves a finding.
- When a finding needs a human decision, summarize the tradeoff and stop; do not
  guess.
- Treat `report.json` as authoritative for locations, evidence, and gates.

## Do not

- Do not expose an instance to a network without confirming authentication is in
  front of it.
- Do not delete a custom node or a model file. Disable or quarantine it by moving
  it aside, so a false positive is recoverable.
- Do not execute a flagged node or load a flagged model to "check" it.
- Do not rotate, move, or print a live secret. Flag it for the credential owner.
- Do not restart or redeploy a production service on your own.
- Do not run `comfyharden restore --apply` without operator confirmation. It is
  the one command that changes the instance; the dry-run (no `--apply`) is safe
  and only writes a plan. Every other ComfyHarden command only reads and reports.

## Gates you must honor

Every action in `FIXES.md` carries a gate.

- `auto`: reversible, low-risk config edits with a clear rollback. Safe to apply.
- `review-required`: apply only after the operator confirms.
- `human-only`: never applied by an agent. Deleting anything, rotating a
  credential, redeploying, or changing a system you were not authorized to touch.

If in doubt, treat a change as `human-only` and explain why.
