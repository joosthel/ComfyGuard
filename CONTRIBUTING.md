# Contributing to ComfyGuard

Thanks for your interest. ComfyGuard is a read-only security evaluator for
ComfyUI deployments. This repository is currently at the design and specification
stage: the concept, threat research, check catalog, reporting contract, snapshot
format, and agent skills are here; the Python implementation follows. Contributions
are welcome at both stages.

## Ways to help

- **New checks.** Propose a detection for a ComfyUI security issue not yet covered.
  See the catalog in [docs/CHECKS.md](docs/CHECKS.md) and the machine-readable
  format in [spec/checks.example.yaml](spec/checks.example.yaml).
- **Threat feed entries.** Report a new ComfyUI, ComfyUI-Manager, or custom-node
  CVE, or a known-malicious node, with a primary source.
- **Documentation.** Corrections and clarifications to the docs.
- **Implementation.** Collectors, the check engine, and the report renderers, once
  that work is underway.

For anything non-trivial, open an issue first so we can agree on the approach
before you spend time on a pull request.

## Principles a contribution must respect

These are the constraints that define the tool. A change that breaks one of them
will not be merged.

- **Read-only by default.** `audit`, `verify`, `snapshot`, and `diff` never change
  the scanned instance. Only `restore --apply` may mutate it, and it never
  deletes (it quarantines). See [docs/CONCEPT.md](docs/CONCEPT.md).
- **Never execute untrusted code or data.** Custom nodes are parsed, not run. Model
  files are inspected at the byte and opcode level, never deserialized.
- **Offline-first.** A full run must work air-gapped. No data from a scanned
  deployment leaves the host.
- **Rank, do not just flag.** Every finding carries an independent severity and a
  confidence. Managing false positives is a first-class goal.
- **Defensive use only.** ComfyGuard is for operators assessing deployments they
  control, or reviewers with permission. Do not add exploitation or attack
  features.

## Proposing a new check

1. Pick a domain and an unused ID in that family (for example `EXP-###`, `NODE-###`,
   `MODEL-###`, `DRIFT-###`). The families are listed in
   [docs/CHECKS.md](docs/CHECKS.md).
2. Describe: what it detects, the detection method (a fact the collectors can
   gather), a default severity and confidence, the remediation class, and a
   primary-source reference.
3. Add it to `docs/CHECKS.md` and an example entry to `spec/checks.example.yaml`.
4. If it depends on new data (a CVE or an IOC), cite the primary source in
   `docs/RESEARCH.md`.

Every check should be low-noise. Prefer flagging for review over asserting malice,
and escalate severity only when a capability and a suspicious indicator co-occur.

## Pull requests

- Keep each PR focused on one change.
- Follow the writing style already in the docs: direct and concrete, no marketing
  language.
- Update the relevant docs and examples in the same PR.
- Reference the issue it addresses.

## Reporting security issues

Do not open a public issue for a vulnerability in ComfyGuard itself. See
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
