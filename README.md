# ComfyGuard

Read-only security evaluation for ComfyUI, with a report your coding agent can act on.

ComfyGuard evaluates an existing ComfyUI installation, writes a report, and can
capture and compare full-state snapshots. The report is the basis a developer's
coding agent works from to fix the problems, guided by the agent skills that ship
with the tool. It is built for instances that run on a company or local network,
where the platform hands the security boundary to whoever runs the deployment.

Assessment is read-only: `audit`, `verify`, `snapshot`, and `diff` change nothing
on the instance. The one exception is `restore --apply`, an opt-in, guarded
rollback to a captured snapshot.

This repository currently holds the concept, specification, threat research,
check catalog, reporting contract, snapshot format, agent skills, and example
outputs. It is the design the implementation is built against. Tool name:
ComfyGuard. Command: `comfyguard`. Repository: `ComfyGuard`.

## Why this exists

Generative tools are moving onto real hardware in real production settings: studio
render nodes, company GPU servers, cloud VMs. That is a healthy sign of the field
maturing, and it is exactly why security matters. A powerful tool on strong
hardware, reachable on a network, is a valuable target, and it needs the same
production hygiene as any other networked service.

ComfyUI is designed to run locally and, by its own security policy, trusts anyone
who can reach its URL. Once an instance is on a network, securing it is the
operator's job. Comfy.org has done real work on the parts it owns: the Registry
scans and bans obfuscated custom nodes, ComfyUI-Manager has security levels, and
recent releases moved sensitive data behind protected paths. ComfyGuard covers
the other half, the security of a specific deployment, which only the operator can
see and configure. It complements that work rather than replacing it.

The need is concrete. In 2026 more than a thousand exposed, unauthenticated
ComfyUI instances were hijacked into cryptomining and proxy botnets, and a
critical unauthenticated remote-code-execution flaw (CVE-2026-68771) was
disclosed and patched. The evidence base is in [docs/RESEARCH.md](docs/RESEARCH.md).

## How it works

ComfyGuard assesses; a coding agent fixes. Five commands, four of them strictly
read-only:

- **`comfyguard audit <path>`** Read-only scan across core and versions, exposure
  and access, custom nodes, dependencies, and model files, plus secrets and host
  checks. Produces ranked findings, a single A-to-F grade, and a remediation plan.
  Safe to run on a live instance.
- **`comfyguard verify <path>`** Re-assesses and diffs against a prior report by
  fingerprint, so you can confirm the agent's fixes landed and nothing regressed.
- **`comfyguard snapshot <path>`** Captures the full instance state (versions,
  node commits, pip freeze, launch flags, Manager config, model inventory, and
  per-node file hashes) into one timestamped JSON, restore-compatible with
  ComfyUI-Manager.
- **`comfyguard diff <a> <b>`** Compares two snapshots, or a snapshot against
  live, and reports what changed: a tampered or planted node, a config downgrade,
  or an exposure regression (a compromise indicator), and version changes (the
  "what broke since it last worked" signal).
- **`comfyguard restore <snapshot>`** Rolls back to a snapshot. Read-only by
  default (it writes a plan and a script); the one command that mutates the
  instance, only with `--apply`, and even then it never deletes.

Snapshot before an agent touches anything, and you have a rollback if a fix
breaks. The agent skills in [skills/](skills/) teach Claude Code or any coding
agent how to read the report, apply fixes under clear gates, snapshot first, and
verify. A curated, versioned ComfyUI threat feed (known CVEs and malicious-node
indicators) drives the version and known-bad checks and ships bundled so the tool
works offline. See [docs/SPEC.md](docs/SPEC.md) and
[docs/SNAPSHOT.md](docs/SNAPSHOT.md) for the full specification.

## What it evaluates

- **Core and versions.** ComfyUI and ComfyUI-Manager matched against the threat
  feed of known CVEs.
- **Exposure and access.** Bind address, authentication, TLS, reverse proxy,
  CORS, launch flags, and the Manager security level.
- **Custom nodes.** Static analysis for code-exec, runtime installs, obfuscation,
  network calls, and `install.py` behavior, with provenance and a known-malicious
  list. Nothing is executed.
- **Dependencies.** Declared and installed packages against OSV and the PyPA
  Advisory DB, with pinning and typosquat checks.
- **Model files.** Static pickle inspection of `.ckpt`/`.pt`/`.bin`, without
  loading them.
- **Secrets and host.** Credentials in the environment or config, root execution,
  privileged containers, mounted Docker socket, and directory permissions.

The full catalog is in [docs/CHECKS.md](docs/CHECKS.md).

## Eight best practices for a secure ComfyUI instance

These are the baseline ComfyGuard measures against. They matter most once an
instance is reachable beyond a single local user. ComfyGuard reports where you
stand against them; a coding agent applies the fixes.

1. **Keep ComfyUI on localhost, and reach it through a proxy.** Do not expose it
   directly with a bare `--listen 0.0.0.0`. For remote access, put an
   authenticating, TLS-terminating reverse proxy (nginx, Caddy, Cloudflare
   Access) or a VPN in front, with ComfyUI bound to `127.0.0.1`.
2. **Require authentication for anything beyond a single local user.** ComfyUI
   core has none, so it lives in the proxy or network layer. Treat `--multi-user`
   as storage partitioning, not access control.
3. **Stay current, and set Manager to strong.** Keep ComfyUI core and
   ComfyUI-Manager updated. On a networked instance set the Manager security level
   to `strong`, and keep runtime pip and git installs disabled unless actively
   needed.
4. **Vet custom nodes before installing.** Prefer verified Registry publishers,
   read `install.py` and `requirements.txt`, and avoid nodes that run code at
   import time or need broad network access. Popularity is not a trust signal.
5. **Prefer safetensors over pickle formats.** Treat `.ckpt`, `.pt`, and `.bin`
   files from untrusted sources as code, not data, because they can execute on
   load.
6. **Run with least privilege.** Use a non-root user or container, never
   `--privileged`, never mount the Docker socket, and scope GPU access through the
   proper device mechanism. Do not bind-mount broad host paths.
7. **Keep secrets and egress under control.** Do not put secrets in the process
   environment, because every custom node can read it; use mounted secret files or
   a manager. Restrict outbound network access to what the instance actually
   needs.
8. **Assess before you expose, and re-assess on a schedule.** Scan the instance,
   fix the findings, verify, and repeat. Set `--disable-api-nodes` and
   `--disable-metadata` when those features are not needed.

The standing baseline for agents is in [AGENTS.md](AGENTS.md).

## Design principles

Read-only by default (only `restore --apply` ever changes the instance, and it
never deletes). Never execute untrusted code or data. Offline-first. No
installation into ComfyUI (it inspects from the outside). ComfyUI-aware, not a
generic linter. Rank, do not just flag. Layered detection. Standards-based,
agent-ready output. Deterministic and explainable. The reasoning is in
[docs/CONCEPT.md](docs/CONCEPT.md).

## Output

- `report.json`: structured findings and a bill of materials for nodes,
  dependencies, and models.
- `report.md`: a human summary that leads with the grade.
- `report.sarif`: SARIF 2.1.0, so node findings show up in GitHub code scanning.
- `FIXES.md`: an ordered, gated remediation plan for a coding agent. ComfyGuard
  writes it; it never applies it.
- `snapshot.json`: a full state manifest (from `snapshot`), restore-compatible
  with ComfyUI-Manager.
- `diff.json` / `diff.md`: what changed between two states, as DRIFT findings
  (from `diff`).
- `RESTORE.md` / `restore.sh`: a gated rollback plan and script (from `restore`).

The reporting and remediation contract is in [docs/REPORTING.md](docs/REPORTING.md),
the snapshot and drift format is in [docs/SNAPSHOT.md](docs/SNAPSHOT.md), with
worked examples in [examples/](examples/).

## Planned usage

```
# Assess an installation (read-only, safe anywhere you have access):
comfyguard audit /opt/comfyui --out ./report

# Capture a known-good baseline before anyone touches it:
comfyguard snapshot /opt/comfyui --out ./baseline

# Hand the report to a coding agent (Claude Code or similar) with the skills
# in skills/, then let it work through FIXES.md under the gates.

# Re-assess and diff to verify the agent's fixes:
comfyguard verify /opt/comfyui --against ./report/report.json

# Later, check for drift or tampering against the baseline:
comfyguard diff --against ./baseline/snapshot.json /opt/comfyui

# If a change broke the instance, roll back (dry-run; add --apply to perform it):
comfyguard restore ./baseline/snapshot.json --target /opt/comfyui
```

## Roadmap

1. Assess: `audit` across the core layers, the threat feed, the report, and the
   agent skills.
2. Verify, snapshot, and breadth: `verify` fingerprint diffing; `snapshot` and
   `diff` with the DRIFT family; SARIF; the ML-BOM; secrets and host checks.
3. Restore and freshness: `restore` (plan plus opt-in `--apply`);
   signature-verified feed refresh; YARA family rules; secret scanning; workflow
   analysis.
4. Continuous use: a CI action, scheduled re-scans, and an optional local
   dashboard.

## A note on limits

A clean grade means no known-bad patterns, versions, or configurations were
found. It does not prove a deployment is safe. Static analysis can be evaded by
novel or obfuscated payloads, which is why the design is layered and why
high-assurance environments should pair ComfyGuard with containment: a
least-privilege user, egress filtering, and sandboxing.

## Documentation

- [docs/SPEC.md](docs/SPEC.md): the consolidated specification.
- [docs/CONCEPT.md](docs/CONCEPT.md): problem, principles, architecture, roadmap.
- [docs/CHECKS.md](docs/CHECKS.md): the full check catalog, including the DRIFT
  family.
- [docs/REPORTING.md](docs/REPORTING.md): output formats and the agent remediation
  contract.
- [docs/SNAPSHOT.md](docs/SNAPSHOT.md): the snapshot format, diff/drift detection,
  and the restore model.
- [docs/RESEARCH.md](docs/RESEARCH.md): the threat landscape, prior-art survey, and
  current ComfyUI security posture.
- [AGENTS.md](AGENTS.md): the standing security baseline for agents.
- [skills/](skills/): agent skills for auditing, remediating, and snapshot/restore.
- [spec/checks.example.yaml](spec/checks.example.yaml): the machine-readable
  ruleset format. [spec/snapshot.schema.json](spec/snapshot.schema.json): the
  snapshot JSON Schema.
- [examples/](examples/): sample report, snapshot, diff, and restore artifacts.
