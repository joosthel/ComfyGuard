# ComfyGuard: specification

ComfyGuard is a read-only security suite for ComfyUI. It evaluates an existing
installation and writes a report. The report is the basis a developer's coding
agent works from to fix the problems, guided by the agent skills that ship with
the tool. It is built for instances that run on a company or local network, where
security becomes the operator's responsibility.

Every command is strictly read-only and changes nothing on the instance.
ComfyGuard only writes its own report artifacts. For a rollback point and
restoring, use ComfyUI-Manager's built-in snapshot feature; ComfyGuard does not
reimplement it.

This is the consolidated specification. The deeper architecture is in
[CONCEPT.md](CONCEPT.md), the full check catalog in [CHECKS.md](CHECKS.md), the
output and remediation contract in [REPORTING.md](REPORTING.md), the agent skills
in `skills/`, and the evidence base in [RESEARCH.md](RESEARCH.md).

Name: ComfyGuard. Command-line tool: `comfyguard`. Repository:
`ComfyGuard`.

## 1. Why this exists

Generative tools like ComfyUI are moving onto real hardware in real production
settings: shared workstations, studio render nodes, company GPU servers, cloud
VMs. That is a good thing, and it is exactly why security matters. A powerful
tool on strong hardware, reachable on a network, is a valuable target, and it
needs the same production hygiene as any other service that leaves a laptop.

ComfyUI is designed to run locally and, by its own security policy, trusts anyone
who can reach its URL. The moment an instance is put on a network, the platform
hands the security boundary to the operator. Comfy.org has done meaningful work
on the parts it owns: the Registry scans and bans obfuscated nodes, ComfyUI-Manager
has security levels, and recent releases moved sensitive data behind protected
paths. ComfyGuard covers the other half: the security of a specific deployment,
which only the operator can see and configure. It complements that work; it does
not replace it.

## 2. What it is: a read-only advisor

ComfyGuard reads, evaluates, and writes a report. It never touches the instance.
The actual fixing is done by a separate coding agent that the operator runs, using
the skills in `skills/`. This split is deliberate: the tool that assesses a
production server should not also mutate it, and keeping it read-only is what makes
it safe to run anywhere. For a rollback point and restoring, use ComfyUI-Manager's
built-in snapshot feature; ComfyGuard does not reimplement it.

One Python CLI, run against a ComfyUI install path. `audit` (implemented) assesses
and writes the report; `verify` (planned) re-assesses and diffs the report to
confirm fixes. Both are read-only.

### `comfyguard audit`

Read-only. Safe to run on a production instance. It evaluates five core layers
plus two extensions and writes the report:

1. **Core and versions.** ComfyUI and ComfyUI-Manager versions matched against a
   curated feed of known ComfyUI CVEs and advisories.
2. **Exposure and access.** Bind address, authentication, TLS, reverse proxy,
   CORS, launch flags, and the ComfyUI-Manager security level.
3. **Custom nodes.** Static analysis of each node (code-exec, subprocess,
   obfuscation, network calls, `install.py` behavior), git provenance, and a
   known-malicious list. Nothing is executed.
4. **Dependencies.** Pinning, direct-URL/git installs, typosquat-shaped names, and
   known-malicious pins from the bundled feed. ComfyGuard runs fully offline, so
   live CVE lookups (OSV, PyPA) are out of scope; pair it with `pip-audit` for that.
5. **Models.** Static pickle inspection of `.pt`/`.ckpt`/`.bin` files, without
   deserializing them.
6. **Secrets** (extension). Credentials in the environment, config, or saved
   workflows.
7. **Host and container** (extension). Root execution, privileged containers,
   Docker socket mounts, and directory permissions.

Output: `report.json`, `report.md` (human, leads with an A-to-F grade), and
`FIXES.md` (the agent remediation plan). These are the only files it writes.
`report.sarif` is planned.

### `comfyguard verify` (planned)

Read-only. Re-assesses the installation and diffs the result against a prior
report by finding fingerprint, to confirm fixes landed and nothing regressed.
Until it ships, re-run `audit` and diff the two reports (findings carry stable
fingerprints).

## 3. How fixing happens: the report plus agent skills

ComfyGuard produces the plan; a coding agent carries it out. To make that
reliable, the tool ships agent skills in `skills/` that teach a coding agent how
to read the report and act on it safely:

- **Where the data is.** `report.json` is the source of truth; `FIXES.md` is the
  ordered, gated, human-and-agent-readable plan.
- **What each finding means** and how to read its severity, confidence, location,
  evidence, and suggested fix.
- **The gates.** Every action is `auto`, `review-required`, or `human-only`. The
  agent must honor them: apply only `auto` directly, confirm `review-required`
  with the operator, and never apply `human-only` (delete, rotate a credential,
  redeploy).
- **The loop.** Make one change, re-run `comfyguard audit`, confirm the finding
  cleared by fingerprint, then move on.

The standing baseline an agent should enforce is in [AGENTS.md](../AGENTS.md); the
per-scan, instance-specific plan is `FIXES.md`. The skills point at both.

## 4. The ComfyUI threat feed

A curated, versioned JSON feed is a first-class component. It holds the known
ComfyUI, Manager, and custom-node CVEs and the malicious-node IOCs (directory
names, file hashes, bad pip pins). It ships bundled so the suite works offline,
and it can be refreshed from a pinned, signature-verified source when a network
is available. Keeping this feed current is the ongoing expert-maintained asset
that keeps the suite useful as the ecosystem changes, without touching the engine.

## 5. Design principles

1. Strictly read-only. Every command writes only its own report artifacts and
   never edits, installs, removes, or restarts anything on the instance. For a
   rollback point and restoring, use ComfyUI-Manager's snapshot feature.
2. Never execute untrusted code or data. Nodes are parsed, not run. Models are
   inspected at the opcode level, not loaded.
3. Offline-first. A full run works air-gapped. No deployment data leaves the host.
4. No installation into ComfyUI. It inspects from the outside, unlike tools that
   run as a custom node inside the very process they are meant to watch.
5. ComfyUI-aware, not a generic linter.
6. Rank, do not just flag. Severity and confidence are separate, to keep false
   positives manageable.
7. Layered detection: signatures, capability-plus-indicator heuristics, and
   allowlist-based model inspection.
8. Agent-ready output. The report is designed to be consumed and acted on by a
   coding agent, with the skills to guide it.
9. Standards-based: JSON, SARIF 2.1.0, a CycloneDX ML-BOM, and a plain-language
   `FIXES.md`.
10. Deterministic and explainable: same input and ruleset produce the same
    output, with stable fingerprints for run-to-run diffing.

## 6. Architecture in one paragraph

Checks are pluggable rule modules that read typed facts produced by independent
collectors (install, Manager, nodes, dependencies, models, secrets, host, and an
opt-in authorized network probe). The engine runs the versioned ruleset against
the facts, de-duplicates and scores the findings, assigns the grade, and renders
the report. ComfyUI depth accrues over time as new rules and new feed entries,
not as engine rewrites. Full detail in [CONCEPT.md](CONCEPT.md).

## 7. Roadmap

1. **Assess.** `audit` across the core layers, the threat feed, `report.json`,
   `report.md`, and `FIXES.md`, plus the agent skills. Covers most documented
   incident classes on its own.
2. **Verify and breadth.** `comfyguard verify` with fingerprint diffing; SARIF
   output; the CycloneDX ML-BOM; and broader offline check coverage.
3. **Freshness.** Signature-verified feed refresh; YARA family rules; secret
   scanning with baselines; and workflow and PNG-metadata analysis.
4. **Continuous use.** A CI action, scheduled re-scans, and an optional local
   dashboard.

## 8. Success criteria

- One command tells an operator whether an instance is safe to expose, with a
  clear grade and the reasons, and changes nothing on the instance.
- A coding agent can read `FIXES.md`, apply the fixes under their gates, and
  re-run `audit` to prove they worked.
- The whole thing runs offline, is safe to run on production, and installs nothing
  into ComfyUI.

## 9. Non-goals

- It is not a fixer. Assessment changes nothing; a separate agent does the
  forward fixing, and ComfyUI-Manager's snapshot feature provides the rollback.
- It is not a runtime firewall, antivirus, or sandbox.
- It does not replace the Comfy Registry or ComfyUI-Manager; it audits how they
  are configured and what they installed.
- Static analysis cannot prove a node or model is safe; a clean grade means no
  known-bad patterns, versions, or configurations were found.
- It is not an incident-response or forensics tool.
