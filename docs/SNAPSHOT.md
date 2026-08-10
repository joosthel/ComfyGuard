# Snapshot, diff, and restore

ComfyGuard can capture the full state of a ComfyUI instance, compare two states
to see what changed, and produce a rollback. This is the reversibility layer that
makes agent-driven fixes safe (snapshot before, roll back if broken) and, through
`diff`, a tamper and drift detector: an unexpected modification is a compromise
indicator, and a version change answers "what changed since it last worked."

This document is the reference for the snapshot format and the `snapshot`, `diff`,
and `restore` commands. It builds on the architecture in [CONCEPT.md](CONCEPT.md),
the finding schema in [REPORTING.md](REPORTING.md), and the check catalog in
[CHECKS.md](CHECKS.md).

## The read-only invariant, and the one exception

`audit`, `verify`, `snapshot`, and `diff` are strictly read-only. They read state
and write only their own output artifacts to an output directory you choose. They
never change the ComfyUI instance.

`restore` is the single exception, and only when you pass `--apply`. Without
`--apply` it is also read-only: it writes a rollback plan and a runnable script,
and changes nothing. With `--apply` it performs the rollback. That is the only way
any ComfyGuard command mutates an instance, and it is heavily guarded (see
Restore below).

## snapshot: capture full state

A snapshot is a second rendering of the same facts an `audit` already collects.
The collectors (Install, Manager, Node, Dependency, Model, Host, and the opt-in
Network probe, see [CONCEPT.md](CONCEPT.md) section 4) build a typed fact store;
`audit` renders it as findings, `snapshot` renders it as a state manifest. The
only extra collection cost is hashing.

```
comfyguard snapshot /opt/comfyui --out ./snap
```

Output is a single timestamped JSON. `audit --emit-snapshot` also drops one during
a normal scan, so an assessment doubles as a baseline.

### Format: a superset of the ComfyUI-Manager snapshot

ComfyUI-Manager already has a snapshot feature with a five-field JSON (core commit,
git nodes with commit hashes, registry-node versions, single-file nodes, and a pip
freeze). ComfyGuard does not reinvent it. It embeds a byte-compatible copy of
that exact object as `manager_snapshot`, so a standalone copy can be restored by
`comfy node restore-snapshot` unchanged, and wraps it in an envelope that adds
what Manager omits.

| Block | Contents | Collector |
|---|---|---|
| `manager_snapshot` | The exact Manager five-field object: `comfyui`, `git_custom_nodes`, `cnr_custom_nodes`, `file_custom_nodes`, `pips` | Manager, Node |
| `core` | Version and commit, branch, remote, dirty flag (Manager records only the commit) | Install |
| `launch` | The launch flags: `--listen`, `--enable-cors-header`, `--tls-*`, `--disable-api-nodes`, `--disable-metadata`, `--disable-all-custom-nodes`, `--whitelist-custom-nodes`, `--enable-manager`, `--disable-manager-ui`, `--max-upload-size`, `--base-directory`, and the launch source (systemd, docker, script) | Install |
| `manager_config` | `security_level`, `allow_pip_install`, `allow_git_url_install`, channel, config path, and whether the config sits on the legacy web-reachable path | Manager |
| `tls_proxy` | TLS on or off, keyfile and certfile presence (not contents), proxy detected, proxy-auth signature | Install, Network |
| `nodes` | Per node: name, path, source, repo, commit, version, disabled, and a per-node `tree_hash` for tamper detection (on by default) | Node |
| `dependencies` | Python version, pip freeze, optional hash pins, declared requirements per node | Dependency |
| `models` | Path, format, and size plus modified-time; sha256 only under `--hash-models` | Model |
| `host` | OS, python, pytorch, container, user and uid, privileged, docker socket mounted | Host |
| `env_allowlist` | Environment variable names and presence only, never values | Host |

Plus `schema_version`, `kind`, `tool`, `ruleset_version`, `created_at`, a
whole-snapshot `fingerprint`, and `target`. A filled example is in
[examples/sample-snapshot.json](../examples/sample-snapshot.json); the standalone
Manager-format copy is in
[examples/sample-manager-snapshot.json](../examples/sample-manager-snapshot.json).

### Hashing defaults

- **Node source files are hashed by default.** They are small, and the hash is the
  tamper signal that lets `diff` catch a modified node whose git commit did not
  change. A compact per-node `tree_hash` is the default; `--deep` records a
  per-file table so `diff` can point at the exact file.
- **Models are metadata-only by default** (size and modified-time). Model
  directories are often tens of gigabytes, so full hashing is opt-in with
  `--hash-models`. Without it, `diff` still detects added, removed, or resized
  models, but not a same-size content swap.

### Secret safety and storage

`env_allowlist` records variable names and presence, never values, consistent with
the no-exfiltration principle. Snapshots are written to the output directory you
choose. ComfyGuard does not write into the ComfyUI tree; the Manager-format copy
is placed into `user/__manager/snapshots/` only by `restore --apply`.

## diff: compare two states

```
comfyguard diff old-snapshot.json new-snapshot.json         # offline, two snapshots
comfyguard diff --against baseline.json /opt/comfyui        # snapshot vs live
```

`diff` compares each block as added, removed, or changed, and emits findings in a
new **DRIFT** check family. DRIFT findings use the exact finding schema in
[REPORTING.md](REPORTING.md), so they feed the same A-to-F grade, `report.sarif`,
and `FIXES.md` with no special handling. The full DRIFT catalog is in
[CHECKS.md](CHECKS.md). It has two sub-classes:

- **Security indicators (tamper and compromise):** a node file changed without its
  commit changing (DRIFT-001), a model swapped (DRIFT-005), a config downgrade
  (DRIFT-008), an exposure regression (DRIFT-009), a host regression (DRIFT-010).
- **Stability drift (production breakage):** a node updated (DRIFT-004), a
  dependency version changed (DRIFT-007), the core version changed (DRIFT-011).

`diff --against` is effectively an incremental audit: a DRIFT that moves a version
into a known-vulnerable range raises the matching PATCH finding, and a newly
appeared node (DRIFT-002) is run through the NODE static-analysis checks. The
grade model is unchanged: a high-confidence tamper (DRIFT-001) produces an F, the
same as a known-malicious node.

## restore: roll back to a snapshot

`restore` is dry-run by default and mutating only with `--apply`.

### Default (read-only): a plan and a script

```
comfyguard restore snapshot.json --target /opt/comfyui
```

This writes, to the output directory only:

1. A restore plan (`RESTORE.md` plus a JSON block) using the action shape from
   [REPORTING.md](REPORTING.md) section 4.
2. A runnable `restore.sh` that a human, a coding agent, or CI executes. It
   **delegates to `comfy node restore-snapshot`** for the node and pip rollback,
   and **compensates for the two gaps** in Manager's restore:
   - Manager's modern restore does not re-checkout the core ComfyUI commit, so the
     script adds an explicit `git checkout <core.commit>` (quarantining a dirty
     working tree, never discarding it).
   - Manager's pip restore is off by default and always skips torch and nvidia
     packages, so the script passes the pip-restore flags and emits the exact
     `pip install` lines for the pinned dependencies, including torch and nvidia,
     with hashes where available.
   It then re-applies the launch flags and `security_level` that the Manager
   format does not carry, as gated config edits.
3. The Manager-format snapshot copy, so the rollback also works through the
   Manager UI or `comfy node restore-snapshot` directly.

An example plan and script are in
[examples/sample-restore.md](../examples/sample-restore.md) and
[examples/restore.sh](../examples/restore.sh).

### With `--apply`: the one write path

```
comfyguard restore snapshot.json --target /opt/comfyui --apply
```

ComfyGuard performs the rollback itself. This is the only command that mutates an
instance, and every guardrail is required:

- It takes a fresh pre-restore snapshot first, as an automatic rollback point.
- It **never deletes.** Nodes or models not in the snapshot are quarantined by
  moving them aside, so a mistake is recoverable and evidence is preserved.
- It refuses to run against a serving instance without `--force`.
- It does not touch torch or nvidia packages, or secrets, without an explicit
  opt-in.
- It honors the gates in [REPORTING.md](REPORTING.md) section 4.3.
- It writes an audit log of every command it runs.

### Confirming a rollback

After a restore, `comfyguard diff --against snapshot.json <target>` should return
an empty diff, which proves the instance matches the baseline again, including the
core-commit and pip compensations. `comfyguard verify` against the pre-change
report confirms the security posture.

## The agent workflow

The [comfyguard-restore](../skills/comfyguard-restore/SKILL.md) skill teaches a
coding agent to take a snapshot before the first change, roll back through the
plan if a fix breaks the instance, and confirm with `diff`. Combined with the
remediation skill, this is what makes agent fixes safe: there is always a captured
known-good state to return to.

## Open items

- Node hash depth defaults to a compact per-node `tree_hash`; `--deep` gives a
  per-file table for tamper localization.
- Snapshot signing is a later addition. Until then, `diff` raises DRIFT-012 when a
  baseline's fingerprint cannot be validated, so a poisoned baseline cannot
  silently mask a change.
