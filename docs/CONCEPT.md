# Concept and architecture: ComfyGuard

`ComfyGuard` is a read-only security suite for ComfyUI with five commands:
`audit` (assess and write a report), `verify` (re-assess and diff against a prior
report to confirm fixes landed), `snapshot` (capture full instance state),
`diff` (compare two states and report drift/tamper), and `restore` (roll back to a
snapshot). `audit`, `verify`, `snapshot`, and `diff` change nothing on the
instance; `restore` changes it only with the opt-in `--apply` flag. Forward fixing
is done by a separate coding agent that reads the report, guided by the agent
skills that ship with the tool. The command model is specified in
[SPEC.md](SPEC.md), and snapshot/diff/restore in [SNAPSHOT.md](SNAPSHOT.md).

This document covers the assessment core (the read-only engine behind `audit`, and
the fact store that `snapshot`/`diff` also render). It inspects an installation and
its surroundings (core version, ComfyUI-Manager, custom nodes, Python dependencies,
model files, workflows, secrets, and host/network posture), scores what it finds
against a catalog of ComfyUI-specific checks, and writes a report designed to be
read by a human and by an automated remediation agent.

This document covers the problem framing, the design principles that constrain
every decision, the architecture, the scan phases, and the roadmap. The evidence
behind the threat model is in [RESEARCH.md](RESEARCH.md). The itemized checks are
in [CHECKS.md](CHECKS.md). The output contract is in [REPORTING.md](REPORTING.md).

## 1. The problem

ComfyUI is built to run on localhost and trusts anyone who can reach its URL. Its
maintainers say so directly in `SECURITY.md`, and they classify network exposure
as the operator's responsibility, out of scope for the project's own
vulnerability program. When a team moves ComfyUI onto a shared network, a
company VLAN, or a cloud VM, the entire security burden shifts to whoever runs
it, and the platform will not patch its way out of a bad configuration.

At the same time the attack surface is unusually wide for a creative tool:

- The `/prompt` API executes an arbitrary node graph with no authentication by
  default. Reaching it plus any code-capable node equals remote code execution.
- Custom nodes are arbitrary Python, loaded at startup, from a large ecosystem
  with a documented history of info-stealers, miners, and supply-chain
  compromises.
- Model checkpoints in pickle-based formats can execute code when loaded.
- Manager, present on most installs, has had a recurring series of
  authorization-bypass RCEs.

The consequences are already being realized at scale: repeated measurement
studies found more than a thousand exposed, unauthenticated instances each, and
two 2026 botnet campaigns turned exposed ComfyUI hosts into miners and credential
harvesters. See [RESEARCH.md](RESEARCH.md) sections 1 and 4.

No maintained tool assesses a whole deployment against this specific surface. The
pieces exist in adjacent ecosystems (Python SAST, dependency scanners, pickle
scanners, secret scanners), but nothing assembles them with knowledge of
ComfyUI's node and workflow model, checks live posture, matches versions to the
ComfyUI and Manager CVEs, and emits standard machine-readable output. That is the
gap `ComfyGuard` fills.

## 2. What it is and is not

**It is** an assessment tool: point it at an installation directory (and
optionally a reachable URL you are authorized to test), and it produces a ranked,
evidence-backed, machine-readable report plus a human summary.

**It is not** a fixer, a firewall, a runtime sandbox, or an antivirus product.
Assessment (`audit`, `verify`, `snapshot`, `diff`) never edits the deployment,
never runs node code, and never deserializes a model file; it writes only its own
reports and snapshots. Forward fixing is the job of a separate coding agent that
reads the report under the guidance of the shipped agent skills. The one action
ComfyGuard itself can take on an instance is `restore --apply`, an opt-in,
guarded rollback to a captured snapshot, which never deletes (it quarantines). It
does not replace ComfyUI-Manager or the Comfy Registry; it audits how they are
configured and what they installed. The remediation contract for the consuming
agent is in [REPORTING.md](REPORTING.md), the snapshot/restore model is in
[SNAPSHOT.md](SNAPSHOT.md), and the skills are in `skills/`.

**Intended use** is authorized self-assessment: an operator evaluating a
deployment they control, or a reviewer with permission, ideally before the
instance is exposed to a network and on a schedule after. The active
network-probe mode is opt-in, defaults to localhost, and requires the operator to
assert authorization. See section 8.

## 3. Design principles

These are hard constraints, not preferences. Every check and output decision is
tested against them.

1. **Read-only and non-destructive.** The scanner opens files for reading,
   reads process and container metadata, and (only when explicitly asked)
   performs safe, non-exploitative network probes. It writes nothing except its
   own report, to a path the operator chooses. This is what makes it safe to run
   against a production instance.

2. **Never execute untrusted code or data.** Node code is analyzed statically
   (parsed into an AST, never imported or run). Model files are inspected at the
   byte and opcode level, never deserialized. This rules out the whole class of
   "the scanner got popped by the thing it was scanning."

3. **Offline-first.** A full scan runs air-gapped. Vulnerability and IOC data are
   bundled and can be refreshed from a pinned, verifiable source when a network
   is available, but no data from the scanned deployment ever leaves it. This
   matters for the target audience: instances on private company networks.

4. **ComfyUI-aware, not a generic linter.** The scanner understands
   `custom_nodes/` layout, `NODE_CLASS_MAPPINGS`, `WEB_DIRECTORY`, `install.py`,
   the Registry `pyproject.toml` format, `extra_model_paths.yaml`, Manager's
   `config.ini` and security levels, the real endpoint set, and which node class
   names correspond to known-vulnerable nodes. Findings are expressed in those
   terms, which is what makes them actionable and low-noise.

5. **Rank, do not just flag.** Every finding carries an independent severity
   (CVSS 4.0 based) and a confidence. A bare `eval` in a node is not the same as
   `eval` on attacker-controlled input inside an import-time hook, and the report
   must say so. Managing false positives is a first-class goal, learned from the
   documented failure modes of pure denylist scanners.

6. **Layered detection.** Combine fast signatures (known-bad hashes, IOC lists,
   YARA) with capability-plus-indicator heuristics (the GuardDog pattern) and
   allowlist-based model inspection (the Fickling approach). No single technique
   is trusted alone, because each has documented bypasses.

7. **Standards-based, agent-ready output.** Findings serialize to a stable JSON
   schema, to SARIF 2.1.0 for GitHub code scanning, and to a CycloneDX ML-BOM.
   On top of that sits an ordered remediation plan written for an automated
   coding agent, with explicit guardrails on what may be auto-applied.

8. **Deterministic and explainable.** Same input, same ruleset version, same
   output, including stable finding fingerprints for run-to-run diffing. Every
   finding names the rule, the evidence, and a citation. No opaque scoring.

## 4. Architecture

The tool is a Python 3.10+ package with a plugin-style collector and check model.
The pipeline is: discover the target, collect facts, run checks against those
facts, correlate and de-duplicate, score, and render.

```
                          ComfyGuard
                              |
        +---------------------+----------------------+
        |                     |                      |
   discovery            collectors               ruleset
  (find install,   (produce Facts about       (versioned check
   Manager, URL)     the deployment)           definitions)
        |                     |                      |
        +----------+----------+                      |
                   v                                 |
              Fact store  ------------->  check engine (checks
             (typed, in-memory            consume Facts, emit
              inventory)                   Findings)
                                                 |
                                                 v
                                    correlate / dedupe / score
                                                 |
                          +----------------------+----------------------+
                          v                      v                      v
                    machine report          SARIF 2.1.0          agent remediation
                    (JSON + ML-BOM)      (code scanning)        plan (ordered, gated)
                                                 |
                                                 v
                                        human report (Markdown/HTML)
```

### 4.1 Collectors

Each collector gathers facts from one part of the deployment and is independent
and skippable, so a scan degrades gracefully when a data source is missing (for
example, no Docker, or no reachable URL).

- **Install collector.** Locates the ComfyUI root, resolves the core version and
  git commit, reads `cli_args` as configured (launch script, systemd unit,
  Docker `CMD`/compose, or a live `/system_stats` probe), and inventories
  directories and overrides.
- **Manager collector.** Detects ComfyUI-Manager (custom-node install or
  `--enable-manager`), resolves its version, and reads `config.ini`
  (`security_level`, `allow_pip_install`, `allow_git_url_install`, channels).
- **Node collector.** Walks `custom_nodes/`, parses each node's Python into an
  AST, reads `requirements.txt`, `install.py`, `pyproject.toml` `[tool.comfy]`,
  and records import-time (module top-level) code separately from runtime code
  because import-time code runs at ComfyUI startup. It also parses the node's
  browser JavaScript under `WEB_DIRECTORY` for the WEB family (external calls,
  DOM and eval sinks, credential reads), since that code runs in the operator's
  browser.
- **Dependency collector.** Resolves declared dependencies (per node and global)
  and, when available, the installed environment (`pip` metadata), for SCA.
- **Model collector.** Enumerates model files across the configured roots,
  classifies format (safetensors and gguf as structurally safe; ckpt, pt, pth,
  bin, pkl as pickle-bearing), and records size and a content sniff (the real
  magic bytes, not the extension).
- **Workflow collector.** Parses workflow and API JSON files and PNG metadata
  chunks, mapping referenced node classes and scanning parameter values.
- **Host collector.** Reads process owner, container `USER`, `HostConfig`
  (`--privileged`, mounts, Docker socket), capabilities and seccomp posture,
  resource limits, file permissions on sensitive dirs, and the process environment
  for secret-shaped values. It also runs the IOC scan: rootkit preload
  (`/etc/ld.so.preload`), immutable or hidden miner artifacts, rogue persistence
  (cron, systemd, `authorized_keys`), and reachable lateral-movement services
  (Docker `2375`, Redis), matched against the threat feed.
- **Network collector (opt-in).** Performs safe, read-mostly probes against an
  authorized target URL: banner and version fingerprint, presence of an auth
  challenge, CORS header value, TLS presence and quality, the security response
  headers and whether `/ws` is behind auth (the gateway family), and reachability
  of high-signal endpoints. It uses existence-oracle style probes (a
  200-versus-403 on a known in-tree file) rather than exfiltrating anything. It
  never posts a payload to `/prompt` and never calls a state-changing endpoint.

Collectors emit typed **Facts** into an in-memory store. Facts are the only thing
checks see, which keeps checks pure and testable and keeps collection (which
touches the messy real world) separate from judgment.

### 4.2 Ruleset and check engine

Checks are data-driven where possible and code where necessary. A check reads
Facts and yields zero or more Findings. The catalog is versioned (a ruleset
version stamped into every report) so results are reproducible and so a report
can be re-evaluated later against a newer ruleset.

Detection techniques available to checks:

- **AST matching** for node code: dangerous sinks (`eval`, `exec`, `compile`,
  `os.system`, `subprocess` with a shell or dynamic argument, `pickle.load`,
  `torch.load` without `weights_only=True`, `marshal`, `ctypes`), obfuscation
  shapes (decode-then-exec, dynamic import string assembly), and import-time side
  effects. Bandit and the Ruff "S" rules can be wrapped here; ComfyUI-specific
  rules are additive.
- **Capability-plus-indicator correlation.** A network call alone is common and
  benign; a network call to a hardcoded IP or a Discord/paste/anonymous-file-host
  domain, combined with reads of credential paths, is a stealer signature. Checks
  raise severity when capability and indicator co-occur in the same unit, which
  is how false positives are kept down.
- **Signature and IOC matching.** Known-malicious node names, known-bad package
  pins, dropped-file names, and YARA family rules, refreshed from a pinned feed.
- **Pickle opcode inspection** for model files, using an allowlist of provably
  safe operations rather than a denylist of known-bad ones, with content
  sniffing so a mislabeled extension or an unexpected archive container cannot
  cause a silent skip.
- **Version-to-advisory matching** for core, Manager, and known-vulnerable
  nodes, keyed on both package metadata and git commit, with a source-level
  fallback probe where version data is ambiguous (see [RESEARCH.md](RESEARCH.md)
  section 7).
- **Dependency hygiene**: pinning, direct-URL/git installs, typosquat-shaped
  names, and known-malicious pins from the bundled feed. Live CVE lookups (OSV,
  PyPA) are out of scope so the tool stays fully offline; operators run `pip-audit`
  separately for that.
- **Secret scanning** (regex plus entropy) with a baseline-file workflow so
  acknowledged false positives stay quiet on later runs.

### 4.3 Correlation, scoring, and rendering

After checks run, the engine de-duplicates overlapping findings (for example a
node flagged by both a version-CVE match and an AST rule), correlates related
findings into a single higher-level risk where appropriate, assigns a
deployment-level risk grade from the finding mix, and renders the outputs.

Scoring keeps severity and confidence separate. The deployment grade is driven by
the highest-confidence critical findings first, so one confirmed
"networked and unauthenticated" result dominates the grade regardless of how many
low-severity style issues exist. See [REPORTING.md](REPORTING.md) for the grade
model.

### 4.4 Snapshots and drift

The same fact store that `audit` renders as findings, `snapshot` renders as a
state manifest. It is a second renderer, not a second engine: the collectors and
facts are identical, and the only extra collection cost is hashing (per-node
source files by default, models only under `--hash-models`). `diff` is a
comparison lens over two such manifests (or one manifest versus live), producing
DRIFT findings that reuse the finding schema, grade, and outputs unchanged, so a
compromise indicator (a node file changed without its commit changing) grades the
same F as a known-malicious node. `restore` renders a manifest back into a
rollback: read-only by default (a plan plus a script that delegates to
`comfy node restore-snapshot`), and mutating only with the opt-in `--apply`. This
whole layer is specified in [SNAPSHOT.md](SNAPSHOT.md); it is what makes agent
fixes reversible.

## 5. Scan phases (what a run does, in order)

1. **Discover.** Find the ComfyUI root and Manager, resolve versions and commit,
   determine how the instance is launched and configured, and (if a URL was
   provided and authorized) confirm it is ComfyUI.
2. **Collect.** Run every applicable collector to build the Fact store. This is
   the only phase that touches the deployment, and it only reads.
3. **Evaluate.** Run the ruleset against the Facts to produce Findings.
4. **Correlate and score.** De-duplicate, correlate, and assign severities,
   confidences, and the deployment grade.
5. **Report.** Emit the machine report (JSON plus ML-BOM), SARIF, the agent
   remediation plan, and the human summary.

A scan is intended to be fast enough to run in CI on a node repository and
thorough enough to run as a pre-exposure gate on a full install.

## 6. The remediation-agent workflow

The distinctive output is a remediation plan written to be executed by an
automated coding agent, with the scanner staying strictly read-only. The split of
responsibility is deliberate: the scanner observes and proposes; a separate agent,
with its own guardrails and the operator's authorization, acts.

The plan orders work so that the safest, highest-value actions come first and
risky actions are gated:

1. **Contain.** Quarantine known-malicious nodes and model files (by moving them
   aside or disabling load, never by silent deletion), and recommend egress
   restriction. High value, but flagged review-required because it changes what
   the instance does.
2. **Harden configuration.** Bind to loopback or a private interface, put an
   authenticating TLS proxy in front, remove permissive CORS, set a safe Manager
   security level and install flags, set `--disable-api-nodes` and
   `--disable-metadata` where appropriate. These are concrete, reversible edits
   to launch scripts, systemd units, compose files, and `config.ini`, which an
   agent can draft precisely.
3. **Patch.** Upgrade core, Manager, and vulnerable nodes to fixed versions.
   Auto-draftable, but gated behind a test-and-confirm step because upgrades can
   break workflows.
4. **Handle secrets.** Move secrets out of the shared process environment into
   mounted files or a secrets manager, and flag credentials that need rotation
   by their owner.
5. **Verify.** Run `comfyguard verify` to re-assess and diff against the prior
   report by finding fingerprint, so the agent (and the operator) can confirm each
   finding is actually resolved and nothing regressed. `verify` is read-only too;
   it only writes a diff report.

Each action in the plan carries an `auto` / `review-required` / `human-only`
gate, a precise target (file and location, or config key), the proposed change,
and a rollback note. The gates constrain the consuming agent, not ComfyGuard,
which applies nothing. Destructive actions (deleting a model or node, rotating a
live credential, redeploying) are never `auto`. The agent skills in `skills/`
teach an agent to honor these gates. The full contract is in
[REPORTING.md](REPORTING.md).

## 7. Roadmap

**Phase 1, MVP (offline static core).** Install, Manager, node, dependency,
model, and host collectors. AST-based node checks, dependency SCA, pickle
inspection, version-to-CVE matching, host and Manager config checks. JSON and
SARIF output, human Markdown report. This alone covers the majority of the
documented incident classes.

**Phase 2, deployment posture and agent plan.** Opt-in network collector (safe
probes), the CORS/TLS/exposure checks, the CycloneDX ML-BOM, and the agent
remediation plan format with gating. This is the point at which the tool serves
its stated purpose: evaluating an instance before it is exposed to a network.

**Phase 3, breadth and freshness.** Refreshable IOC and advisory feeds with
signature verification, a YARA family ruleset, secret-scanning with baselines,
workflow and PNG-metadata analysis, and a maintained map of known-vulnerable
node versions.

**Phase 4, integrations and continuous use.** CI action that uploads SARIF,
scheduled re-scans with drift diffing, and an optional local dashboard. Possible
later: a community, machine-readable advisory feed for custom nodes, which does
not exist today and is a real ecosystem gap (see [RESEARCH.md](RESEARCH.md)
section 5).

**Explicitly later or out of scope for now:** dynamic and behavioral analysis
(running a node in a sandbox to observe it) is powerful but breaks the "never
execute untrusted code" principle, so it would live in a clearly separated,
opt-in component if built at all. The tool does not attempt to be a runtime
protection layer.

## 8. Authorized use and safety posture

The static and host collectors operate on a local installation and are safe to
run anywhere the operator has access. The network collector is different: probing
a running service is only appropriate against targets the operator is authorized
to test. It therefore defaults to localhost, requires an explicit flag and an
authorization assertion for any non-loopback target, performs only
non-exploitative read-mostly probes, never sends a payload to `/prompt` or any
state-changing endpoint, and logs exactly what it did. The tool is a defensive
self-assessment instrument, and the design keeps it on that side of the line.

## 9. Non-goals and limitations

- Static analysis cannot prove a node is safe. A clean report means "no known-bad
  patterns, signatures, versions, or configurations were found," not "this is
  safe to run." The report says this plainly.
- Obfuscation and novel payloads can evade signature and pattern rules. The
  layered design and the allowlist-based model inspection reduce this, but do not
  eliminate it. High-assurance environments should combine `ComfyGuard` with
  containment (least-privilege user, egress filtering, sandboxing).
- Version-to-CVE matching is only as current as the bundled data. The tool
  reports the data's age and the ambiguity around ComfyUI version numbering
  rather than implying certainty.
- The tool audits configuration and artifacts; it cannot see a compromise that
  leaves no static trace, and it is not an incident-response or forensics tool.
