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

## Urgency, the pre-exposure gate, and human decisions

Severity says how bad a finding is if real. For a deployed instance, an operator
also needs to know how urgent it is and whether resolving it is a machine fix or a
human call. Every check carries two extra attributes:

- **Urgency:** `blocker` (must be resolved before an instance is exposed to a
  network or put into production, or fixed immediately if already exposed),
  `urgent` (address promptly on any deployed instance), `standard`, or `hardening`
  (defense in depth). The report can filter to just the blockers.
- **Decision owner:** most findings an agent can draft a fix for. Some are
  inherently a person's call and are marked **human-decision**: whether an
  instance should be reachable at all, accepting an availability or compatibility
  trade-off, taking a possibly-compromised instance offline, rotating a
  credential, deleting data, or a data-retention and compliance choice. For these
  the agent presents the trade-off and stops.

**The pre-exposure gate** is the set of `blocker` checks. An instance should not be
exposed to a company network or the internet until they pass. As a shorthand: no
reachable instance without authentication (EXP, AUTH, API-003, API-008), no
known-malicious node or active-compromise indicator (PATCH-007, IOC), no
unauthenticated-RCE core or Manager version (PATCH-002, PATCH-005), no container
escape surface (HOST-002, HOST-003, HOST-014), and no missing rollback point
(snapshot a baseline first). The full gate list is in the coverage summary.

This urgency model is why the tool aims to be comprehensive: on a production
deployment you want the whole surface checked, then the results triaged by what
blocks exposure, what is urgent, and what is a human decision, rather than a flat
list.

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
| AUTH-004 | Default, blank, or shared credentials on the fronting auth: a proxy Basic Auth with a default or empty password, an auth node left at its default password, or one credential shared by everyone (no per-user identity, no revocation). | High | config |
| AUTH-005 | No multi-factor or SSO on an internet-exposed instance. For a company deployment reachable beyond a private network or VPN, single-factor is a human-decision risk to accept or fix (SSO/MFA at the proxy). | Medium | manual |

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
| API-008 | `/ws` WebSocket reachable unauthenticated. It broadcasts execution status, the running node, progress, and preview images to any connected client. The origin-only middleware is a browser-CSRF guard, not authentication: a non-browser client (curl, websocat) sends no Origin and connects freely. A client can also supply another session's `clientId` and knock its socket off. | High when networked | config |

References: `server.py` (including the `/ws` handler and `clientId` handling),
`app/user_manager.py`, `api_server/routes/internal/internal_routes.py`;
execution.py `SENSITIVE_EXTRA_DATA_KEYS`.

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
| NODE-015 | Node installed from an insecure or non-canonical source: an `http://` (not https) git remote, a fork rather than the Registry or canonical repo, a typosquatted repo name, or a raw git-URL install rather than a verified Registry publisher. | Medium | manual |

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
| DEP-001 | Declared dependency matching the bundled advisory feed (curated known-bad or known-vulnerable pins for the ComfyUI ecosystem). ComfyGuard is offline, so this covers the bundled feed only, not live OSV/PyPA. | Per feed entry | upgrade |
| DEP-002 | Unpinned dependency (no `==` and no hash), which allows a future compromised release to be pulled in. | Low to Medium | config |
| DEP-003 | Direct-URL, `git+http(s)`, or non-PyPI install line in requirements. | Medium | manual |
| DEP-004 | Typosquat-shaped package name: a close edit-distance match to a popular package. | Medium | manual |
| DEP-005 | Known-malicious pinned version (compromised Ultralytics builds and similar). Overlaps PATCH-007. | Critical | quarantine |
| DEP-006 | Installed-package audit: read installed versions from the target's `site-packages` and match them against the bundled feed (offline), catching drift from declared deps. Live OSV of the installed set is out of scope. | Per feed entry | upgrade |

References: Ultralytics compromise; the ComfyGuard bundled feed.

**Scope note.** ComfyGuard runs fully offline and does not query OSV, the PyPA
Advisory DB, or any network service. Dependency checks cover pinning, install
source, typosquats, and the bundled known-bad feed. For live CVE coverage of the
full dependency set, run `pip-audit` or OSV-Scanner as a separate, complementary
step. That live scanning is deliberately out of scope for ComfyGuard.

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
| HOST-011 | Weak container isolation: dangerous Linux capabilities kept (for example `CAP_SYS_ADMIN`) instead of dropped, no seccomp or AppArmor profile, no `no-new-privileges`, or a writable root filesystem. Each turns a node-level RCE into a stronger foothold. | High | config |
| HOST-012 | Base image not pinned: an image tag like `latest` with no digest, so the running image can change silently, and no image scanning or provenance. | Medium | config |
| HOST-013 | No CPU, memory, or GPU resource limits (cgroup or Kubernetes). A single workflow can exhaust the host, and an abused instance can mine at full GPU. Overlaps DOS-003. | Medium to High | config |
| HOST-014 | A lateral-movement service reachable from the ComfyUI host or network: the Docker daemon on TCP `2375`, or a Redis or other backend on its default port with no auth. These are the exact escape and persistence vectors used by the 2026 botnets. | Critical | config |

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

## DOS: availability and resource abuse

Production availability is a real security property and often a human decision
(what to spend on capacity, what to rate-limit). ComfyUI core has no rate limiting.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| DOS-001 | No rate limiting or throttling in front of `/prompt`. The pending queue is unbounded, so a client can flood it. On a networked instance with no rate-limiting proxy, this is a trivial denial of service. | High when networked | config |
| DOS-002 | Upload and storage caps missing or too high: `--max-upload-size` (default 100MB) is the only body limit, with no per-client or total-storage cap, so large or repeated uploads fill `input` and `temp`. | Medium | config |
| DOS-003 | No CPU, memory, or GPU limits on the process or container: one workflow can exhaust the host, and an abused instance can mine at full GPU. Overlaps HOST-013. | Medium to High | config |
| DOS-004 | Unauthenticated disruptive endpoints: repeated `POST /free` thrashes model load/unload, and `POST /interrupt` or `POST /queue` (clear) can cancel or wipe another user's work. | Medium when networked | config |

References: `server.py` (no throttle middleware); `--max-upload-size`, `--reserve-vram`
in `cli_args.py`; SECURITY.md (resource exhaustion is out of scope for the vendor,
so it is the operator's control).

---

## GW: gateway and reverse-proxy hardening

When a proxy fronts the instance (the recommended pattern), audit the proxy.
ComfyUI core sends almost no security headers, so these are the proxy's job.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| GW-001 | Missing security response headers: HSTS, X-Frame-Options (or `frame-ancestors`), X-Content-Type-Options, Referrer-Policy. Core sends none, and its CSP ships only with `--disable-api-nodes` (EXP-007), so the proxy must add them. | Medium | config |
| GW-002 | Weak TLS at the edge: a protocol below TLS 1.2, weak or legacy ciphers, or an expired, self-signed, or hostname-mismatched certificate. | High to Medium | config |
| GW-003 | WebSocket not behind the proxy auth: the classic gotcha where `auth_basic` is on `location /` but the separate `/ws` block does not re-declare it, so `/ws` (API-008) bypasses authentication. | High | config |
| GW-004 | Server or version banner disclosed: the proxy passes ComfyUI/aiohttp's default `Server` header rather than stripping it. | Low | config |
| GW-005 | Path allowlisting instead of whole-app auth: the proxy exposes only some paths but leaves `/prompt`, `/internal/*`, `/userdata/*`, `/ws`, or Manager endpoints reachable. Front the entire app with auth; do not allowlist paths. | High | config |

References: `server.py` (middleware and headers); the nginx WebSocket-auth pattern
(ComfyUI discussion #2786); SECURITY.md (operator responsibility).

---

## WEB: browser-side node extensions

Custom nodes ship JavaScript via `WEB_DIRECTORY`, served at `/extensions` and
loaded into the ComfyUI UI, same-origin, with no sandbox or review. It runs in the
browser of anyone using the instance. Analyzed statically alongside NODE.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| WEB-001 | A node's browser JS calls an external host: `fetch`, `XMLHttpRequest`, `WebSocket`, or an injected script/image to a non-self origin, especially a hardcoded IP, a webhook, or a paste or anonymous-file host. Exfiltration surface in the operator's browser. | High | manual |
| WEB-002 | Node JS uses a DOM-injection or dynamic-eval sink on non-constant input: `eval`, `new Function`, `innerHTML`/`outerHTML`, `document.write`, or `insertAdjacentHTML`. First-party-origin XSS. | Medium to High | manual |
| WEB-003 | Node JS reads browser credentials (cookies, `localStorage`/`sessionStorage`, or a Comfy.org token) and pairs it with an outbound call (co-occurs with WEB-001). | High | manual |
| WEB-004 | Many untrusted extensions load with no CSP (EXP-007) on a networked or multi-user instance. Recommend disabling custom frontend JS (as hosted platforms do by returning an empty extension list) or gating it. | Medium | manual |

References: `nodes.py` (`load_custom_node`, `WEB_DIRECTORY`, `EXTENSION_WEB_DIRS`),
`/extensions`; Snyk's hosted-platform `getExtensions` override; docs.comfy.org
custom-nodes JavaScript overview.

---

## DATA: data protection, retention, and privacy

Relevant for company deployments and data-protection regimes such as GDPR. Several
of these are human decisions, not agent fixes.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| DATA-001 | Output, input, and temp directories grow unbounded with no retention or cleanup. Both a disk-fill denial of service and an accumulation of potentially personal data. | Medium | manual |
| DATA-002 | Generated outputs and uploads exposed without access control on a networked or multi-tenant instance: `/view` and `/internal/files/{output,input,temp}` serve them unauthenticated, so personal or sensitive images are readable by anyone who can reach the instance. | High when networked | config |
| DATA-003 | Output images embed the full prompt and workflow as PNG metadata by default (`--disable-metadata` not set). Sharing an image leaks prompts, node graphs, file paths, and any secret in them. Overlaps FLOW-004. | Low to Medium | config |
| DATA-004 | Input, temp, or output files are group- or world-readable, or on shared storage, so one tenant or a lower-privileged user can read another's data. | Medium | config |
| DATA-005 | No documented data-processing or retention policy for a company deployment. A compliance and governance decision for the operator, not an agent fix. | Info | manual |

References: `nodes.py` (`SaveImage` metadata); `/view` and `/internal/files`
(unauthenticated); `--disable-metadata`; `folder_paths` directory handling.

---

## IOC: active-compromise indicators

Unlike DRIFT, which needs a baseline, these scan the host and install for
signatures of an instance that is already compromised, drawn from the documented
ComfyUI incidents and refreshed from the threat feed. Any hit is urgent and a
human decision: take the instance offline and investigate.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| IOC-001 | LD_PRELOAD rootkit: `/etc/ld.so.preload` present, or an unexpected `LD_PRELOAD` in the process environment (for example `libpam_cache.so`), used by the 2026 botnet to hide miner files and processes. | Critical | manual |
| IOC-002 | Hidden or immutable miner artifacts: files marked immutable (`chattr +i`), hidden dotfiles in `/var/tmp`, `/dev/shm`, `/usr/lib/locale`, `/var/cache/man`, or `/var/spool/cron` matching miner drop patterns, or masqueraded process names (`khugepaged_*`, `nv_uvm_*`, `.cpu`, `.gpu`). | Critical | manual |
| IOC-003 | Unexpected persistence: cron entries, systemd units, autostart entries, or `authorized_keys` additions that fetch or run a remote payload. | Critical | manual |
| IOC-004 | Backdoor node or poisoned startup workflow: a node such as `comfyui_perf_monitor` that re-fetches a payload on a timer, or an auto-run workflow (for example `user/default/workflows/default.json`) containing code-exec node calls or a curl/wget/urllib payload fetch. | Critical | quarantine |
| IOC-005 | Known command-and-control or mining indicators: references to feed-listed C2 hosts or mining pools (for example the 2026 campaign's hosts and the Kryptex pools), Discord-webhook exfiltration, or anonymous-file-host uploads, found in node code, config, or observed egress. | Critical | manual |
| IOC-006 | Known-malicious pip pin or node directory present: a superset of ComfyUI-Manager's small startup denylist plus the 2026 botnet indicators. Overlaps PATCH-007 and DEP-005; the IOC framing is "already installed on this host." | Critical | quarantine |

References: Censys GHOST report; The Hacker News NadMesh; LLMVISION and Ultralytics
incidents; ComfyUI-Manager `security_check` denylist; the ComfyGuard threat feed.

---

## OPS: monitoring, logging, and incident readiness

Production readiness, and mostly human decisions. Core logging is minimal,
in-memory (about 300 lines), unauthenticated, and actively cleared by attackers,
so detection must come from outside the application.

| ID | Detects and how | Severity | Fix |
|---|---|---|---|
| OPS-001 | No external access logging or audit trail. Core logs are in-memory and lost on restart, and nothing records who queued what. Recommend reverse-proxy access logs and centralized logging. | Medium | manual |
| OPS-002 | No outbound egress monitoring or alerting for the C2 and mining-pool indicators in the IOC family. | Medium | manual |
| OPS-003 | No host integrity monitoring or endpoint detection watching for the IOC signatures (`ld.so.preload`, immutable binaries, rogue cron, `/dev/shm` payloads). | Medium | manual |
| OPS-004 | No backup or recovery for models, workflows, and config. This is business continuity and the clean-restore path after a compromise; a ComfyGuard baseline snapshot is the minimum. | Medium | manual |
| OPS-005 | No incident-response plan or defined owner for a networked or company deployment. A readiness decision for the operator. | Info | manual |

References: `app/logger.py` (in-memory logs, default capacity 300); `/internal/logs`
(unauthenticated); the ComfyGuard snapshot as a baseline.

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
- Availability and resource abuse (queue flooding, GPU mining amplification): DOS.
- Reverse-proxy and gateway hardening (headers, TLS, the WebSocket auth gotcha):
  GW plus API-008.
- Browser-side node extensions (XSS and exfiltration in the operator's browser):
  WEB.
- Data protection and privacy for company and GDPR deployments: DATA.
- Whether the instance is already compromised (the 2026 botnet IOCs): IOC.
- Production monitoring, logging, and incident readiness: OPS.
- Post-baseline compromise and instability (tampered node, planted node, config
  downgrade, exposure regression): DRIFT, via `comfyguard diff`.

## Pre-exposure gate (blocker checks)

These must pass before an instance is exposed to a company network or the
internet, and should be fixed immediately if it is already exposed:

- Reachable with no authenticating layer: EXP-001, EXP-002, EXP-005, AUTH-001,
  AUTH-004.
- Unauthenticated RCE or high-risk surface reachable: API-003, API-008,
  PATCH-002, PATCH-005.
- Known-malicious node or active-compromise indicator: PATCH-007, any IOC finding.
- Container or host escape and lateral-movement surface: HOST-002, HOST-003,
  HOST-014.
- No rollback point captured (take a `comfyguard snapshot` baseline first).

The ruleset is versioned. New CVEs and IOCs are added as advisory and incident
data, so the catalog grows without changing the engine.
