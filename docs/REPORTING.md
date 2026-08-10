# Reporting contract

`ComfyHarden` emits a set of artifacts. This document defines each, the finding
schema they share, the deployment risk grade, and the agent remediation plan with
its guardrails. Concrete examples are in `examples/`.

The core artifacts from an `audit`:

1. **Machine report** (`report.json`): the full, structured result. The source of
   truth. Includes a CycloneDX ML-BOM inventory of nodes, dependencies, and model
   files.
2. **SARIF** (`report.sarif`): SARIF 2.1.0 for GitHub code scanning and other
   SARIF consumers, so findings appear as inline annotations in a PR or the
   security tab.
3. **Agent remediation plan** (`FIXES.md`, plus the same actions inside
   `report.json`): an ordered, gated set of actions written for an automated
   coding agent to carry out. ComfyHarden writes it; it never applies it.
4. **Human report** (`report.md` or `.html`): a readable summary that leads with
   the grade and the top findings.

`comfyharden verify` produces a diff-of-findings report that compares a fresh scan
against a prior one by finding fingerprint. It is read-only too.

The `snapshot`, `diff`, and `restore` commands add three more artifacts, all
sharing the same finding schema and grade where they carry findings (see
[SNAPSHOT.md](SNAPSHOT.md)):

5. **Snapshot** (`snapshot.json`): a full state manifest, plus a byte-compatible
   ComfyUI-Manager copy. Written by `snapshot`; read-only.
6. **Drift report** (`diff.json` + `diff.md`): what changed between two states, as
   DRIFT findings that feed the same grade and SARIF. Written by `diff`; read-only.
7. **Restore plan** (`RESTORE.md` + `restore.sh` + a Manager-format snapshot):
   an ordered, gated rollback. Written by `restore`; read-only unless `--apply` is
   passed, the one command that mutates an instance.

All of these derive from the same findings and facts, so they never disagree. The
reports and snapshots are versioned by a `ruleset_version` and a `schema_version`
so an artifact stays interpretable as the tool evolves. DRIFT findings from `diff`
use the exact finding object below, so they render into `report.sarif` and the
grade with no special handling.

## 1. The finding object

Every finding, in every artifact, uses this shape. Fields marked optional are
present when applicable.

```json
{
  "fingerprint": "e3b0c442-node-eval-a1b2",
  "check_id": "NODE-001",
  "title": "eval() on non-constant input in custom node",
  "category": "custom-node-code",
  "severity": "high",
  "cvss": {"version": "4.0", "score": 8.5, "vector": "CVSS:4.0/AV:N/AC:L/..."},
  "confidence": "high",
  "location": {
    "kind": "file",
    "path": "custom_nodes/example-node/nodes.py",
    "start_line": 142,
    "end_line": 142,
    "symbol": "ExampleNode.execute"
  },
  "evidence": "result = eval(user_expression)",
  "description": "The node passes a user-controllable value to eval(), which allows arbitrary Python execution when the node runs.",
  "impact": "A crafted workflow parameter reaching this node executes code as the ComfyUI process user.",
  "remediation": {
    "class": "manual",
    "auto_fixable": false,
    "summary": "Replace eval with a safe expression evaluator or an explicit allowlist of operations.",
    "action": "Refactor ExampleNode.execute to avoid eval; if arithmetic is needed, use ast.literal_eval or a sandboxed evaluator.",
    "rollback": "Revert the node file to its prior version.",
    "gate": "review-required"
  },
  "references": [
    {"type": "advisory", "id": "CVE-2024-21577", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21577"},
    {"type": "policy", "url": "https://docs.comfy.org/registry/standards"}
  ]
}
```

Key design points:

- **`fingerprint`** is a stable hash of the check, the normalized location, and
  the matched pattern. It lets two scans of the same deployment be diffed to see
  what was fixed, what regressed, and what is new. It is how the verify step in
  the remediation plan confirms a finding is actually resolved. This per-finding
  fingerprint is distinct from a snapshot's whole-snapshot `fingerprint` (a hash
  over the canonical state, used by `diff` to detect a poisoned or mismatched
  baseline, DRIFT-012).
- **`severity` and `confidence` are separate.** Severity is the impact if real;
  confidence is how sure the scanner is that it is real. A consumer can filter on
  either. The deployment grade (section 3) weights them together.
- **`location.kind`** is one of `file`, `endpoint`, `config`, `process`,
  `container`, `dependency`, or `model`, so a finding can point at a line of node
  code, a CORS header, a `config.ini` key, or a running container equally well.
- **`evidence`** is redacted for secret findings (a fingerprint and a location,
  never the secret value), consistent with the read-only, no-exfiltration
  principle.
- **`remediation.gate`** is `auto`, `review-required`, or `human-only`, and is the
  contract the remediation agent must honor.

## 2. SARIF mapping

Each `check_id` becomes a SARIF `rule`, and each finding becomes a `result` whose
`ruleId` is the check ID, `level` maps from severity (critical and high to
`error`, medium to `warning`, low and info to `note`), and `locations` maps from
the finding `location` when it is a file. Non-file findings (endpoints, config,
containers) are emitted with a logical location and a `partialFingerprints` entry
built from the finding fingerprint, so GitHub deduplicates them correctly across
runs. The CVSS vector and references travel in the result's `properties` bag.

This means a node repository can run `comfyharden` in CI, upload the SARIF, and
get node-code findings as inline PR annotations with no bespoke dashboard.

## 3. Deployment risk grade

The report leads with a single grade (A to F) so a non-specialist can read the
result at a glance. The grade is deterministic and driven by the worst confirmed
findings, not by counting:

- **F**: any Critical finding at high confidence (for example, networked and
  unauthenticated; a known-malicious node present; an unauthenticated-RCE core
  version). One is enough.
- **D**: any Critical at lower confidence, or multiple High findings.
- **C**: at least one High finding.
- **B**: only Medium findings.
- **A**: only Low or Info findings.

The rationale is explicit in the report: the grade names the specific findings
that set it, so it is never a black box. A single confirmed
"exposed and unauthenticated" result produces an F regardless of how clean the
rest of the deployment is, which matches the real-world risk ordering in
[RESEARCH.md](RESEARCH.md).

The report also carries counts by severity and by category for trend tracking,
but those never override the worst-finding grade.

## 4. The agent remediation plan

The plan is the reason the report is machine-readable. It turns findings into an
ordered sequence of actions that an automated coding agent can execute under the
operator's supervision, while ComfyHarden itself stays strictly read-only. The
scanner proposes; the agent, separately and with authorization, acts. This plan
is written to `FIXES.md` (a Markdown rendering) and carried in `report.json`. The
agent skills in `skills/` teach a coding agent to read it and honor the gates
below.

### 4.1 Ordering

Actions are grouped into phases that run in this order, because doing them out of
order can either miss the highest risk or break the instance:

1. **Contain**: quarantine known-malicious nodes and model files, recommend
   egress restriction. First, because these are active threats.
2. **Harden configuration**: bind to loopback or a private interface, add an
   authenticating TLS proxy, remove permissive CORS, set a safe Manager security
   level and install flags, set `--disable-api-nodes` and `--disable-metadata`
   where appropriate. These are precise, reversible edits.
3. **Patch**: upgrade core, Manager, and vulnerable nodes to fixed versions.
   After config hardening, because an exposed instance should be closed off
   before a possibly-disruptive upgrade.
4. **Secrets**: relocate secrets out of the shared environment; flag credentials
   for rotation by their owner.
5. **Verify**: run `comfyharden verify` to diff by fingerprint and confirm each
   finding is resolved and nothing regressed.

### 4.2 Action shape

```json
{
  "id": "act-003",
  "phase": "harden-configuration",
  "addresses": ["EXP-001", "EXP-002", "AUTH-001"],
  "gate": "review-required",
  "title": "Bind ComfyUI to loopback and front it with an authenticating TLS proxy",
  "target": {"kind": "file", "path": "deploy/comfyui.service"},
  "change": {
    "summary": "Remove --listen 0.0.0.0; bind 127.0.0.1; add a reverse proxy config with auth and TLS.",
    "diff_hint": "ExecStart: drop '--listen 0.0.0.0'; add reverse-proxy unit (nginx/Caddy) template provided.",
    "provided_artifacts": ["deploy/nginx-comfyui.conf.template"]
  },
  "verification": "Re-scan: EXP-001, EXP-002, AUTH-001 should clear; GET /system_stats over the network should now require auth.",
  "rollback": "Restore the prior ExecStart line and remove the proxy unit.",
  "risk_if_applied": "Remote users lose direct access until they authenticate through the proxy."
}
```

### 4.3 Guardrails (non-negotiable)

- **Gates are mandatory.** `auto` actions are limited to reversible,
  low-blast-radius config edits with a clear rollback. Everything with real
  consequence is `review-required`. Anything destructive or externally visible is
  `human-only`.
- **`human-only` always includes:** deleting a node or model file (quarantine by
  moving aside is the auto/review path instead), rotating a live credential,
  redeploying or restarting a production service, and any change to a system the
  operator has not authorized the agent to modify.
- **No silent deletion, ever.** Malicious artifacts are moved to a quarantine
  location and recorded, never removed outright, so a false positive is
  recoverable and evidence is preserved.
- **No execution of the flagged artifact.** The remediation flow never runs a
  suspected-malicious node or loads a suspected-malicious model to "confirm" it.
- **Every action is reversible or has a stated rollback.** If an action cannot be
  rolled back, it is `human-only` and says why.
- **Verify closes the loop.** The plan is not complete until a re-scan confirms
  the addressed findings cleared by fingerprint. An agent reporting "fixed"
  without a passing re-scan is not following the contract.

### 4.4 What the agent still cannot decide

The plan deliberately leaves some things to a person: whether an instance should
be network-reachable at all, whether a flagged node is needed enough to keep and
sandbox rather than remove, and whether an upgrade's compatibility risk is
acceptable for a given set of production workflows. The plan surfaces these as
explicit decisions with the tradeoffs stated, rather than guessing.

## 5. Example artifacts

- `examples/sample-report.json`: a machine report with a representative spread of
  findings across domains, including the ML-BOM inventory.
- `examples/sample-agent-remediation-plan.md`: the human rendering of the plan
  derived from that report, showing the phases and gates.

These are illustrative and hand-authored to specify the format precisely. They
are the target the implementation is written against.
