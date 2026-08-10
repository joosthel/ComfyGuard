# Check catalog

This is the catalog of security checks `ComfyGuard` runs, grouped by domain. It is
the human-readable companion to the machine-readable ruleset (format shown in
`spec/checks.example.yaml`). Every check has a stable ID, a detection method, a
default severity, and a remediation class that tells an automated agent how (and
whether) it may act.

Severities follow CVSS 4.0 bands: Critical, High, Medium, Low, Info. Severity and
confidence are independent; a check can be High severity but Low confidence, and
the report carries both. The evidence base for these checks is
[RESEARCH.md](RESEARCH.md).

**Remediation classes** (how the agent remediation plan may treat a finding):

- `config`: agent can draft an exact edit to a launch script, systemd unit,
  compose file, or `config.ini`. Apply is review-required.
- `upgrade`: agent can draft a version bump or update command. Apply is
  review-required and test-gated (upgrades can break workflows).
- `quarantine`: agent can move-aside or disable a node or model file. Never a
  silent delete. Review-required.
- `secret`: agent can relocate a secret out of the shared environment. Credential
  rotation is human-only.
- `manual`: needs human judgment. The agent summarizes and proposes, does not
  apply.
- `context`: informational or inventory. No fix action.

The single most important framing check is EXP-001 combined with AUTH-001:
"reachable over a network with no authenticating layer." Per ComfyUI's own
security policy, exposure itself is the operator's risk, so the scanner treats it
as a top-tier finding on its own, without waiting for a specific CVE to match.

---

## EXP: exposure and network configuration

Detected from the configured launch (flags in the launch script, systemd unit,
Docker `CMD` or compose, or a live `/system_stats`/header probe when the network
collector is enabled).

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| EXP-001 | Bind address is non-loopback: bare `--listen` (binds all interfaces) or `--listen <public/LAN IP>`. | Critical when also reachable and unauthenticated, else High | config |
| EXP-002 | No authenticating layer in front: an unauthenticated `GET /system_stats` returns 200 with no auth challenge and no known auth proxy signature. | Critical | config |
| EXP-003 | CORS downgrade: `--enable-cors-header` set (especially the bare `*` form, observable as `Access-Control-Allow-Origin: *`). This does not just permit CORS, it *replaces* ComfyUI's default origin-only CSRF middleware with a permissive one that also sends `Access-Control-Allow-Credentials: true`, removing the built-in anti-CSRF/anti-DNS-rebinding guard. | High | config |
| EXP-004 | TLS absent on a non-loopback listener: plain HTTP, no `--tls-keyfile`/`--tls-certfile` and no TLS-terminating proxy. Credentials and API keys travel in clear text. | High | config |
| EXP-005 | Dangerous combination: `--enable-cors-header *` together with a non-loopback `--listen`. Any website the operator's browser visits can script the instance. | Critical | config |
| EXP-006 | Default exposure fingerprint: ComfyUI answering on `:8188` on a public interface (the signature actively scanned by the 2026 botnets). Hardening and awareness. | Medium | config |
| EXP-007 | No Content-Security-Policy on an exposed instance: ComfyUI emits its CSP header only when `--disable-api-nodes` is set. On a networked server that does not need cloud API nodes, recommend `--disable-api-nodes` (which also blocks outbound calls) so a CSP is present, or inject a CSP at the proxy. | Low to Medium | config |

References: ComfyUI `cli_args.py` and `server.py` (the origin-only vs CORS
middleware, and `create_block_external_middleware` which gates the CSP on
`--disable-api-nodes`); SECURITY.md; Censys/The Hacker News GHOST campaign; Snyk
and UpGuard exposure studies.

---

## AUTH: authentication and access control

ComfyUI core has no authentication. These checks catch the absence, and common
misconceptions and weak add-ons.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| AUTH-001 | No access control on a networked instance: core provides none, and no reverse-proxy auth (`WWW-Authenticate`, Cloudflare Access, oauth2-proxy, Authelia) or auth node is detected. | Critical when networked | config |
| AUTH-002 | `--multi-user` present and possibly mistaken for authentication. It is storage partitioning only, with no password or server-side identity. | Info to Medium | manual |
| AUTH-003 | Weak add-on auth: a single-shared-password node (for example ComfyUI-Login) as the only control, or an auth node without TLS in front. Note the auth node itself runs as trusted in-process code. | Medium | config |

References: SECURITY.md; ComfyUI issues #987, #10653, discussion #5165; community
auth nodes (ComfyUI-Login, comfyui-basic-auth, ComfyUI-Sentinel).

---

## API: endpoint exposure and information disclosure

Relevant when the instance is networked. Detected by the opt-in network collector
against an authorized target, or inferred from version plus configuration.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| API-001 | `/internal/logs/raw` reachable unauthenticated: live server console tailing to the network. High-signal, low false positive. | High | config |
| API-002 | `/internal/folder_paths` reachable: discloses real filesystem paths for every model type, useful recon for traversal. | Medium | config |
| API-003 | ComfyUI-Manager endpoints reachable unauthenticated (`/api/manager/*`, `/customnode/*`, `/manager/reboot`): historically the largest RCE surface on exposed instances. | Critical | config |
| API-004 | `/upload/image` reachable unauthenticated: an arbitrary-write primitive that becomes RCE when chained with a vulnerable consuming node (see PATCH-002). | High | config |
| API-005 | `/history` may return Comfy.org API keys: source-level observation that `/history` does not strip `SENSITIVE_EXTRA_DATA_KEYS` the way `/queue` does. Confidence Low, verify by probing the response. | Medium (Low confidence) | manual |
| API-006 | System and inventory disclosure via `/system_stats`, `/features`, `/models`, `/object_info`, `/extensions`: reveals OS, versions, installed models and node classes. | Low | config |
| API-007 | Vulnerable node classes present and reachable: `/object_info` (or the node inventory) contains classes tied to known RCE, such as `LoadTrainingDataset`, `ACE_ExpressionEval`, `BuildColorRangeHSVAdvanced`, or raw shell-exec nodes. | High | quarantine |

References: `server.py`, `app/user_manager.py`,
`api_server/routes/internal/internal_routes.py`; execution.py
`SENSITIVE_EXTRA_DATA_KEYS`.

---

## PATCH: known-vulnerable versions

Version and commit matching for core, Manager, and specific nodes, against
bundled advisory data. Keyed on package metadata and git commit, with a
source-level fallback where version strings are ambiguous.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| PATCH-001 | Core below 0.28.0, which shipped the path-traversal fixes (`LoadImage`, model-preview) and stored-XSS fixes (`/view`, `/userdata`): CVE-2026-56670/56672/56673, GHSA-pj59-g5vv-74q4. This is the single highest-value version check; "core >= 0.28.0, ideally latest (0.31.x)" also pairs with a positive stay-current recommendation. | High | upgrade |
| PATCH-002 | Core vulnerable to `LoadTrainingDataset` pickle RCE, CVE-2026-68771, unauthenticated 9.8. Detect by version/commit and node presence. | Critical | upgrade |
| PATCH-003 | ComfyUI-Manager below 3.38 (with core below 0.3.76): config-exposure RCE, CVE-2025-67303. | High | upgrade |
| PATCH-004 | ComfyUI-Manager below 3.39.2 or 4.0.x below 4.0.5: CRLF config injection, CVE-2026-22777. | High | upgrade |
| PATCH-005 | ComfyUI-Manager below 3.31: install-flow authorization bypass RCE, CVE-2025-45076. | Critical | upgrade |
| PATCH-006 | Known-vulnerable custom node versions: ComfyUI-Impact-Pack below 7.6.2 (CVE-2024-21575), ComfyUI-Bmad-Nodes `eval` (CVE-2024-21576), ComfyUI-AceNodes `ACE_ExpressionEval` (CVE-2024-21577), Manager below 2.51.1 (CVE-2024-21574). | High to Critical per node | upgrade |
| PATCH-007 | Known-malicious artifacts present (IOC match): node dirs such as `ComfyUI_LLMVISION` and the `upscaler-4k` family; pip pins such as `ultralytics==8.3.41/8.3.42/8.3.45/8.3.46`; botnet-abused shell-exec nodes. | Critical | quarantine |

References: RESEARCH.md sections 2 to 4; Comfy-Org GHSA pages; VulnCheck; Snyk;
Doyensec; Tencent xlab; ComfyUI-Manager `security_check` denylist.

---

## NODE: custom node static analysis

The scanner parses each node's Python into an AST and analyzes it without
executing it. Import-time code (module top level, run at ComfyUI startup) is
weighted higher than code that only runs when a node executes. Severity rises when
a dangerous capability co-occurs with a suspicious indicator in the same unit.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| NODE-001 | `eval`, `exec`, or `compile` on a non-constant argument. Registry-banned. | High | manual |
| NODE-002 | `os.system`, or `subprocess.*` with `shell=True` or a dynamically built command. | High | manual |
| NODE-003 | Runtime package install: `pip install` via subprocess, `pip.main`, or helper wrappers (`ensure_package`, `install_requirements`) called at import or run time. Registry-banned; Upscaler-4K signature. | High | manual |
| NODE-004 | Obfuscation: base64/zlib/lzma/codecs/marshal decode feeding `exec`/`eval`; PyArmor markers; long single-line encoded blobs; `.pyc`-only modules; string-assembled `__import__`/`getattr` to reach a sink. Registry-banned. | High | manual |
| NODE-005 | Import-time side effects: network calls, file writes, or subprocess at module top level or in `__init__.py`, which execute on ComfyUI startup. | High | manual |
| NODE-006 | Exfiltration-shaped network calls: hardcoded IPs, or requests to Discord/Telegram webhooks, paste sites, or anonymous file hosts (for example gofile.io). LLMVISION and Akira signatures. | High | manual |
| NODE-007 | Credential and wallet access: reads of `~/.ssh`, `~/.aws`, browser profile or login-data paths, crypto wallet paths, keyrings, or a bulk `os.environ` dump. Stealer signature. | Critical | quarantine |
| NODE-008 | Persistence: writes to autostart, registry Run keys, cron, or systemd; AppData executables; hidden+system file attributes; `chattr +i`; LD_PRELOAD. | Critical | quarantine |
| NODE-009 | Download-and-execute: fetch a remote URL, write it to disk, then `chmod +x` and run, or exec its contents. | Critical | quarantine |
| NODE-010 | Unsafe deserialization: `torch.load` without `weights_only=True`, `pickle.load(s)`, `dill`, or `marshal.loads` on file or network input. | High | manual |
| NODE-011 | `install.py` that performs network, exec, or file-write actions beyond declaring dependencies. Install-time RCE surface. | High | manual |
| NODE-012 | Bundled binaries or scripts (`.exe`, `.dll`, `.so`, `.sh`, `.ps1`, `.bat`, `.scr`), or payloads staged in auxiliary folders (`scripts/`, `bin/`, data blobs). Upscaler-4K buried-payload signature. | Medium to High | manual |
| NODE-013 | Sandbox-escape dynamic dispatch: `getattr` on `os`/builtins with an assembled name, or `__builtins__` introspection used to bypass an `eval` filter. Bmad-Nodes bypass. | High | manual |
| NODE-014 | YARA family match against stealer, miner, or loader rules on node files. | High to Critical per rule | quarantine |

References: Comfy Registry Standards (eval/exec, runtime pip, obfuscation bans);
Bandit blacklist and Ruff "S" rules; GuardDog capability-plus-indicator model;
LLMVISION, Upscaler-4K, and Snyk CVE-cluster incidents.

Note on false positives: legitimate nodes do use `subprocess`, `requests`, and
`torch.load`. These checks default to flagging for review, not to declaring
malice, and escalate only on co-occurrence (NODE-006 with NODE-007, or any
NODE-004 obfuscation wrapping a NODE-002 sink).

---

## DEP: dependencies and supply chain

Declared dependencies (per node and global) and, when available, the installed
environment.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| DEP-001 | Declared dependency with a known advisory (OSV or PyPA Advisory DB). | Per advisory | upgrade |
| DEP-002 | Unpinned dependency (no `==` and no hash), which allows a future compromised release to be pulled in. | Low to Medium | config |
| DEP-003 | Direct-URL, `git+http(s)`, or non-PyPI install line in requirements. | Medium | manual |
| DEP-004 | Typosquat-shaped package name: a close edit-distance match to a popular package. | Medium | manual |
| DEP-005 | Known-malicious pinned version (compromised Ultralytics builds and similar). Overlaps PATCH-007. | Critical | quarantine |
| DEP-006 | Installed-environment audit: `pip` metadata matched against OSV for the actually-installed set, catching drift from declared deps. | Per advisory | upgrade |

References: pip-audit, OSV-Scanner, PyPA Advisory DB; Ultralytics compromise.

---

## MODEL: model file safety

Enumerated across configured model roots. Format is classified by content sniff,
not extension, so a mislabeled file cannot cause a silent skip.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| MODEL-001 | Pickle-bearing format present (`.ckpt`, `.pt`, `.pth`, `.bin`, `.pkl`). Inventory and context; escalated by the checks below. | Info | context |
| MODEL-002 | Static pickle-opcode inspection finds a global import or reduce to a non-allowlisted callable (`os`, `sys`, `subprocess`, `builtins`, `eval`, `exec`). Allowlist model, no deserialization. | Critical | quarantine |
| MODEL-003 | Extension/content mismatch: a file presented as safetensors that is actually an archive or pickle, or a pickle mislabeled as `.bin`. The picklescan bypass class. | High | quarantine |
| MODEL-004 | Unexpected archive container (7z or rar where a zip is expected) wrapping a model, which can bypass a scanner while still loading in PyTorch. | Medium to High | quarantine |
| MODEL-005 | safetensors header validation: overlapping offsets, out-of-range lengths, or oversized declared shapes (a denial-of-service and integrity concern, not code execution). | Low | manual |
| MODEL-006 | Provenance unknown: file not present in a known-good hash set. Inventory context to support a human trust decision. | Info | context |

References: Fickling allowlist scanner; modelscan; picklescan GHSA-jgw4-cr84-mqxg;
Hugging Face 7z-container bypass; ComfyUI issue #12245; CVE-2026-68771.

---

## FLOW: workflows and assets

Workflow and API JSON files, and workflow/prompt data embedded in PNG metadata.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| FLOW-001 | Workflow references custom nodes that are not installed or come from an untrusted source, indicating what would be pulled in to run it. | Medium | manual |
| FLOW-002 | Hardcoded secret or API key in workflow JSON (`extra_data`, node parameters). | High | secret |
| FLOW-003 | Workflow contains external fetch URLs feeding load-from-URL nodes (server-side fetch, an SSRF surface). | Medium | manual |
| FLOW-004 | Output metadata embedding is on (`--disable-metadata` not set) while outputs are shared externally, leaking prompts, workflow graphs, and possibly keys in saved PNGs. | Low | config |
| FLOW-005 | Workflow drives an eval/exec-capable node with attacker-influenceable parameters. | High | manual |

References: UpGuard PNG-metadata leak study; `--disable-metadata`; SSRF-shaped
load-from-URL community nodes.

---

## SEC: secrets

Secret material readable by the wrong parties. Uses regex plus entropy detection
with a baseline-file workflow so acknowledged non-secrets stay quiet.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| SEC-001 | Secrets in the process or container environment, readable by every in-process custom node. The Comfy Deploy AWS-key exposure pattern. | High | secret |
| SEC-002 | Secrets in config files, `.env`, `extra_model_paths.yaml`, or node directories with group- or world-readable permissions. | High | secret |
| SEC-003 | Comfy.org API keys (`api_key_comfy_org`, `auth_token_comfy_org`) stored or embedded in saved workflows or PNG metadata. | Medium to High | secret |
| SEC-004 | Generic secret-scan hits (cloud keys, tokens, private keys) across node repos and config, verified where a safe verifier exists. | Per hit | secret |

References: Snyk Comfy Deploy finding; TruffleHog, gitleaks, detect-secrets;
execution.py sensitive-key handling.

---

## HOST: host, container, and process hardening

Read from process and container metadata and filesystem permissions. Requires
local or agent access, not a remote probe.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| HOST-001 | Process runs as root, or container `USER` is root (or unset). | High | config |
| HOST-002 | Container runs `--privileged`. Unnecessary for ComfyUI and removes most isolation. | Critical | config |
| HOST-003 | Docker socket (`/var/run/docker.sock`) mounted into the container. Equivalent to host root. | Critical | config |
| HOST-004 | Broad host bind-mounts (`/`, a home directory) beyond the ComfyUI data directories, widening the blast radius of any node RCE. | High | config |
| HOST-005 | `extra_model_paths.yaml` or a directory override points at a shared, group-writable, or network-mounted path. Includes the symlink-escape risk class. | Medium to High | manual |
| HOST-006 | `custom_nodes`, model, or user directories are group- or world-writable, allowing a lower-privileged user to plant code that loads at startup. | Medium | config |
| HOST-007 | Manager configured unsafely for a networked instance: `security_level` weak or normal-, or `allow_pip_install`/`allow_git_url_install` set to true. Also recommend `--disable-manager-ui` on an exposed server (keeps scheduled tasks, removes the mutating UI and endpoints). | High | config |
| HOST-008 | GPU access granted via `--privileged` instead of the scoped NVIDIA Container Toolkit device mechanism. Overlaps HOST-002. | Medium | config |
| HOST-009 | No outbound egress restriction (no default-deny), so a compromised node can freely exfiltrate or fetch payloads. Configuration and awareness. | Medium | manual |
| HOST-010 | ComfyUI-Manager config on the legacy `user/default/ComfyUI-Manager/` path (pre-`__manager` migration, Manager below 3.38 or core below the System User Protection API): the config is reachable through the core web API and can be tampered with remotely. Cross-references PATCH-003. Fed by the snapshot's `manager_config.config_path_is_legacy`. | High | upgrade |

References: SECURITY.md and community hardening guides; Snyk hosted-platform
findings; ComfyUI-Manager security-level, install-flag, and `__manager` migration
semantics; the `--disable-manager-ui`, `--disable-all-custom-nodes`,
`--whitelist-custom-nodes`, and `--disable-metadata` core flags;
`extra_model_paths.yaml.example`.

**Recommendation checks (enable what ComfyUI already provides).** Beyond the
findings above, an audit surfaces positive recommendations for kiosk, multi-tenant,
or locked-down deployments: enable `--disable-all-custom-nodes` with a
`--whitelist-custom-nodes` allowlist where the node set is fixed; enable
`--disable-metadata` where output images should not carry prompts or workflows;
prefer nodes from verified Registry publishers (a provenance signal, per the
Registry Standards and `comfy node validate`). These reflect features ComfyUI
already ships, so ComfyGuard recommends enabling them rather than flagging a bug.

---

## DRIFT: state change and tamper detection

Emitted by `comfyguard diff` when it compares two snapshots, or a snapshot
against the live instance. DRIFT findings use the same finding schema, grade, and
outputs as every other check (see [SNAPSHOT.md](SNAPSHOT.md) and
[REPORTING.md](REPORTING.md)). Two sub-classes: security indicators (tamper and
compromise) and stability drift (what changed since it last worked).

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| DRIFT-001 | A custom node's source file changed on disk but its git commit is unchanged. Deterministic content should hash identically for a given commit, so this is a tamper indicator, not an update. | Critical to High | quarantine |
| DRIFT-002 | A custom node appeared that was absent in the baseline. The new node is routed through the NODE static-analysis and PATCH known-malicious checks automatically. | High | manual to quarantine |
| DRIFT-003 | A custom node present in the baseline was removed. | Low to Medium | context |
| DRIFT-004 | A node's git commit changed (an update); escalate if the new commit is unknown or unverified. | Medium | context to upgrade |
| DRIFT-005 | A model file's sha256 changed for the same path (substitution). Requires `--hash-models`; otherwise a same-size swap is not detected. | High | quarantine |
| DRIFT-006 | A new model file appeared; escalate if it is a pickle format (cross-references MODEL-002). | Low to Medium | context |
| DRIFT-007 | A dependency version changed; escalate to Critical if the new pin matches a known-bad IOC (cross-references DEP-005, PATCH-007). | Medium to Critical | upgrade |
| DRIFT-008 | Manager config downgrade: `security_level` lowered, `allow_pip_install`/`allow_git_url_install` flipped to true, or the Manager UI re-enabled since the baseline. | High | config |
| DRIFT-009 | Exposure regression: `--listen` widened to non-loopback, `--enable-cors-header` added, TLS flags removed, or a `--disable-api-nodes`/`--disable-metadata`/`--disable-all-custom-nodes` dropped. | High to Critical | config |
| DRIFT-010 | Host regression: process or container user changed to root, `--privileged` added, or the Docker socket mounted since the baseline. | High to Critical | config |
| DRIFT-011 | Core ComfyUI version or commit changed; cross-references PATCH to report if it moved into or out of a vulnerable range. | Medium | context to upgrade |
| DRIFT-012 | Baseline integrity: the snapshot fingerprint or signature will not validate, or its `schema_version` mismatches, so the diff cannot be trusted. | Info to Medium | manual |

References: [SNAPSHOT.md](SNAPSHOT.md); the existing NODE, MODEL, DEP, PATCH, EXP,
and HOST families that DRIFT cross-references rather than duplicates.

---

## Coverage summary

The catalog above is organized so that the highest-real-world-impact classes map
to concrete, testable checks:

- Exposed and unauthenticated instances (the active botnet target): EXP plus
  AUTH plus API.
- Malicious or vulnerable custom nodes (LLMVISION, Upscaler-4K, the Snyk
  cluster): NODE plus PATCH plus DEP.
- Malicious model files (the pickle RCE class, CVE-2026-68771, issue #12245):
  MODEL.
- Manager RCE history: PATCH plus HOST-007 plus API-003.
- Secret and data leakage (UpGuard leaks, Comfy Deploy keys): SEC plus FLOW.
- Host and container weakness that turns a node bug into host compromise: HOST.
- Post-baseline compromise and instability (tampered node, planted node, config
  downgrade, exposure regression): DRIFT, via `comfyguard diff`.

The ruleset is versioned. New CVEs and IOCs are added as advisory and incident
data, so the catalog grows without changing the engine.
