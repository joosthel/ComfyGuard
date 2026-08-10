# Remediation plan (sample)

Generated from `sample-report.json`. Ruleset 2026.08.1. Target `/opt/comfyui`,
core 0.3.62, Manager 3.29.0.

**Deployment grade: F.** Set by two high-confidence Critical findings: the
instance is reachable without an authenticating layer (sec-net-001), and a
known-malicious node is installed (node-mal-001).

This plan is written for an automated coding agent operating under the operator's
supervision. `comfyguard` did not change anything. Each action states a gate. The
agent must honor gates: `auto` may be applied directly, `review-required` needs
operator confirmation, `human-only` is described but never applied by the agent.
Nothing here deletes anything or executes a flagged artifact.

## Phase 1: Contain

**act-001 (review-required) Quarantine the known-malicious node.**
Addresses node-mal-001. Move `custom_nodes/ComfyUI-Upscaler-4K` to
`quarantine/` (do not delete). Then investigate persistence: look for
`AppData/Roaming/DisplayUpdater.exe` and equivalent artifacts on any host that
ran this instance. Rollback: restore from `quarantine/` only if confirmed a false
positive. This node matches an info-stealer campaign, so treat the host as
possibly compromised and escalate to a person.

**act-002 (review-required) Quarantine the dangerous checkpoint.**
Addresses model-001. Move `models/checkpoints/unknown-merge.ckpt` to
`quarantine/`. Do not load it. Prefer a safetensors equivalent from a trusted
source. The file's pickle stream references a shell-exec callable.

**act-003 (human-only) Restrict outbound egress.**
Addresses node-code-001, host-009. Recommend a default-deny egress policy at the
host or network layer, allowing only known model-download hosts and
`api.comfy.org`. Stated as a decision because it affects other workloads.

## Phase 2: Harden configuration

**act-004 (review-required) Bind to loopback and add an authenticating TLS proxy.**
Addresses sec-net-001, sec-net-002. In `deploy/comfyui.service`, remove
`--listen 0.0.0.0` and bind `127.0.0.1`. Add the provided
`deploy/nginx-comfyui.conf.template` (auth plus TLS, with a WebSocket location
block for `/ws`). Verification: re-scan clears EXP-001, EXP-002, AUTH-001, and
`GET /system_stats` over the network now requires auth. Rollback: restore the
prior `ExecStart` and remove the proxy unit. Risk: remote users must authenticate
through the proxy from now on.

**act-005 (auto) Set a safe Manager configuration.**
Addresses host-002. In `user/default/ComfyUI-Manager/config.ini` set
`security_level=strong`, `allow_pip_install=False`, `allow_git_url_install=False`.
This is a reversible config edit with a clear rollback (restore the prior file),
so it is safe to apply directly, then confirm on re-scan.

## Phase 3: Patch

**act-006 (review-required) Upgrade ComfyUI-Manager and core.**
Addresses mgr-cve-001. Back up `user/` first. Upgrade Manager to 3.38+ and core
to 0.3.76+, then run the userdata security migration. Verification: re-scan clears
PATCH-003. Rollback: keep the `user/` backup and the prior versions pinned.

**act-007 (review-required) Upgrade ComfyUI core to the July 2026 fixes.**
Addresses core-cve-001. Upgrade core past the path-traversal and stored-XSS
fixes, then run smoke-test workflows before returning to service. Gate is
review-required because an upgrade can change node behavior.

## Phase 4: Node code and dependencies

**act-008 (review-required) Remove the runtime pip install.**
Addresses node-code-002. In `custom_nodes/handy-tools/__init__.py`, delete the
import-time `pip install` and declare the package in `requirements.txt` instead.
Rollback: revert the file.

**act-009 (review-required) Review the exfiltration-shaped call.**
Addresses node-code-001. Inspect `post_result` in
`custom_nodes/handy-tools/util.py`. Confirm what is sent and to where. If it is
not a required, understood feature, remove or gate it. This is a judgment call,
so it stays with a person plus the agent's summary.

**act-010 (auto) Pin the unpinned dependency.**
Addresses dep-001. In `custom_nodes/handy-tools/requirements.txt`, pin
`somepkg==<known-good version>` with a hash where feasible.

## Phase 5: Secrets

**act-011 (human-only) Relocate and rotate the cloud credential.**
Addresses secret-001. Move `AWS_SECRET_ACCESS_KEY` out of the process environment
into a mounted file with restrictive permissions or a secrets manager. The
credential owner rotates it, because it may already be exposed to every
in-process node. The agent prepares the config change but does not rotate.

## Phase 6: Verify

**act-012 (auto) Re-scan and diff.**
Re-run `comfyguard` and diff against `sample-report.json` by fingerprint. Confirm
sec-net-001, sec-net-002, node-mal-001, model-001, mgr-cve-001, core-cve-001,
node-code-002, host-001, host-002, and dep-001 have cleared, and that no new
findings appeared. The plan is not complete until this passes. node-code-001 and
secret-001 remain open pending the human decisions above.

## Decisions left to a person

- Should this instance be network-reachable at all, or moved behind a VPN or kept
  local?
- Is `handy-tools` needed enough to keep and sandbox, or should it be removed?
- Is the upgrade's compatibility risk acceptable for the current production
  workflows?
