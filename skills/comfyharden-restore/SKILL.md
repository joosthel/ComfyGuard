---
name: comfyharden-restore
description: Use when snapshotting a ComfyUI instance before making changes, or rolling one back to a known-good ComfyHarden snapshot after a fix broke it or a compromise is suspected. Triggers on ComfyHarden snapshot.json / RESTORE.md / restore.sh, or requests to snapshot, roll back, or restore a ComfyUI instance. snapshot and diff are read-only; restore only mutates with --apply.
---

# Snapshotting and rolling back a ComfyUI instance

ComfyHarden can capture an instance's full state and roll it back. Use this to
create a safety net before you change anything, and to recover if a change breaks
the instance or a `diff` shows tampering.

## Before you change anything: snapshot

Always capture a baseline before the first change:

```
comfyharden snapshot <path> --out ./baseline
```

This is read-only. Keep the resulting `baseline/snapshot.json`; it is your rollback
point. If you are also remediating from an audit, snapshot first, then work through
`FIXES.md`.

## Detecting drift and tamper: diff

```
comfyharden diff --against ./baseline/snapshot.json <path>
```

Read-only. It reports what changed since the baseline as DRIFT findings. Treat a
DRIFT-001 (a node file changed with its git commit unchanged) or DRIFT-002 (a new,
unexpected node) as a possible compromise: isolate the instance and tell the
operator before doing anything else.

## Rolling back: restore

`restore` is dry-run by default and writes only a plan and a script:

```
comfyharden restore ./baseline/snapshot.json --target <path>
```

This produces `RESTORE.md`, `restore.sh`, and a Manager-format snapshot. Nothing
is changed. You then either run `restore.sh` step by step under the gates, or, if
the operator authorizes it, run the one mutating form:

```
comfyharden restore ./baseline/snapshot.json --target <path> --apply
```

`restore --apply` is the only ComfyHarden command that changes the instance.

## Rules for restore

- **Snapshot the current state first.** The rollback must itself be reversible.
- **Never delete.** Nodes or models not in the baseline are quarantined by moving
  them aside, never removed. The script and `--apply` both do this; do not
  shortcut it.
- **Re-checkout the core commit and reinstall torch yourself.** Manager's restore
  leaves these two gaps; the generated script fills them. Do not assume
  `comfy node restore-snapshot` alone is a complete rollback.
- **Restart is human-only.** Do not redeploy or restart a production service on
  your own.
- **Do not touch secrets** as part of a restore.

## Confirm the rollback

After restoring, run:

```
comfyharden diff --against ./baseline/snapshot.json <path>
```

An empty diff proves the instance matches the baseline again, including the
core-commit and pip compensations. If findings remain, the rollback is incomplete;
work the remaining DRIFT items. The task is done only when the diff is clean.
