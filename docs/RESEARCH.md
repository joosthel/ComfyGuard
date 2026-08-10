# Research: ComfyUI security landscape (2024 to 2026)

This document records the threat landscape and prior-art survey that the scanner
design is built on. It is the evidence base for the checks in
[CHECKS.md](CHECKS.md) and the design decisions in [CONCEPT.md](CONCEPT.md).

Research window: mid 2024 to August 2026. Where a claim rests on a single
secondary aggregator that could not be confirmed against a primary source (NVD,
a vendor advisory, or the ComfyUI source), it is marked *unconfirmed*. Version
numbers in ComfyUI advisories are inconsistent across trackers (see the note at
the end of this file), so the scanner resolves versions from installed package
metadata and git commits, not from a single quoted string.

## 1. Why this matters now

ComfyUI is designed to run locally and binds to `127.0.0.1` by default. Its own
`SECURITY.md` states the threat model plainly: "anyone with access to the
ComfyUI URL is trusted." Anything that requires `--listen` or other network
exposure is declared out of scope for the project's vulnerability program and
treated as the operator's responsibility. That single policy decision is the
reason a deployment-focused evaluation tool is needed: when an instance is put
on a company network, the security boundary moves entirely to the operator, and
the platform will not patch its way out of an exposed configuration.

The exposure is not theoretical. Two measurement studies and two active botnet
campaigns bracket the problem:

- Snyk Labs (Dec 2024, updated May 2025) found more than 1,000 internet-exposed
  ComfyUI instances, with roughly 64 showing any login protection at all.
- UpGuard (June 2025) found about 2,800 hosts via Shodan; of the reachable
  unauthenticated subset, 60 were actively leaking data (prompts, base64 images
  in PNG metadata, full model and node inventories), including real people's
  photos and at least one deepfake-style workflow.
- The "GHOST" campaign (reported April 2026, Censys and The Hacker News) swept
  cloud ranges for exposed instances, installed a vulnerable code-exec node via
  ComfyUI-Manager when one was not already present, and dropped XMRig plus a
  proxy-for-sale botnet on 1,000+ hosts.
- "NadMesh" (July 2026, XLab) targeted ComfyUI alongside Ollama, n8n, Gradio and
  Open WebUI, using a Shodan-driven recon script, and focused on credential and
  cloud-key theft rather than mining.

## 2. Known vulnerabilities in ComfyUI core

| ID | Component | Class | Severity | Fixed in |
|---|---|---|---|---|
| CVE-2026-68771 | Core, `LoadTrainingDataset` | Unauthenticated pickle RCE via `torch.load` on an uploaded shard file | 9.8 Critical (CWE-502) | PR #14543 (`weights_only=True`) |
| CVE-2026-56673 (GHSA-rvxv-29p8-pxgq) | Core, `LoadImage` and siblings via `/prompt` | Path traversal, file-existence oracle and image exfiltration | 7.5 High (CWE-22, CWE-863) | 0.28.0 |
| GHSA-pj59-g5vv-74q4 | Core, `/experiment/models/preview` | Path traversal via unsanitized `os.path.join` | 7.5 High (CWE-22) | 0.28.0 |
| CVE-2026-56670 (GHSA-rj8c-c4p8-3c5h) | Core, `/view` | Stored XSS via inline SVG, token theft | 8.2 High (CWE-79) | 0.28.0 |
| CVE-2026-56672 (GHSA-53g8-45wq-pcv8) | Core, `/userdata/{file}` | Stored XSS via extension-derived content type | 8.2 High (CWE-79) | 0.28.0 |
| CVE-2025-6107 (GHSA-cq2m-wxm4-pqr4) | Core, `comfy/utils.py` `set_attr` | Dynamic attribute manipulation | 1.3 Low (CWE-913) | disputed / unclear |
| CVE-2026-6591 | Core, `LoadImage` / `get_annotated_filepath` | Path traversal via `Name` param | 5.3 Medium | *unconfirmed, likely overlaps CVE-2026-56673* |
| Issue #12245 (open) | Core, `comfy/checkpoint_pickle.py` | Unsafe unpickle: `find_class` only blocks `pytorch_lightning`, so a crafted `.ckpt`/`.pt`/`.bin` runs code on load | RCE-class | open as of Feb 2026 |

Two structural facts matter more than any single CVE:

1. **The `/prompt` endpoint is the core compromise primitive.** It is
   unauthenticated by default and executes an arbitrary node graph. If any
   installed node can reach a code, file, or network sink (many custom nodes
   can), reaching `/prompt` is arbitrary code execution as the ComfyUI process
   user. The path-traversal and pickle CVEs above are specific instances of a
   general truth: reachable `/prompt` plus the right node equals RCE.

2. **Pickle deserialization is a standing risk, not a fixed bug.** PyTorch 2.6
   flipped `torch.load`'s `weights_only` default to `True`, but ComfyUI still
   loads legacy `.ckpt` files that fail under that setting, so the unsafe path
   remains reachable in places (CVE-2026-68771 was exactly this), and
   `checkpoint_pickle.py` still delegates to the stock unpickler for anything
   outside a one-module denylist.

## 3. Known vulnerabilities in ComfyUI-Manager

ComfyUI-Manager (originally `ltdrdata/ComfyUI-Manager`, now
`Comfy-Org/ComfyUI-Manager`) is the de facto package manager and, historically,
the single largest RCE surface on exposed instances. It shows a repeating
pattern: an authorization or install-path control is added, then bypassed.

| ID | Class | Severity | Fixed in |
|---|---|---|---|
| CVE-2024-21574 | Pip dependency injection via the unvalidated `pip` field on `/customnode/install` | 10.0 Critical | Manager 2.51.1 |
| CVE-2025-45076 | Security-level and allowlist bypass on the install queue, via the never-validated `channel` field and a `selected_version=unknown` path | 10.0 Critical | Manager 3.31 |
| CVE-2025-67303 | Manager config stored under `user/default/`, reachable and writable through the core web API, so an unauthenticated attacker can downgrade the security level or redirect the node channel to reach RCE | 7.5 High (CWE-420) | Manager 3.38 with core 0.3.76 |
| CVE-2026-22777 | CRLF injection into `config.ini` via query parameters, tampering with security settings | 7.5 High (CWE-93) | Manager 3.39.2 / 4.0.5 |

Manager's own defenses, which the scanner audits rather than reimplements:

- **Security levels** `weak`, `normal-`, `normal` (default), `strong`, from most
  to least permissive. `normal-` only unlocks high-risk operations (git-URL
  install, pip install, non-default-channel install) when the server is bound to
  loopback, decided by an `ipaddress.is_loopback` check on the `--listen` value.
  `strong` blocks those operations always.
- **Decoupled install flags.** As of 2026, `allow_git_url_install` and
  `allow_pip_install` are explicit `config.ini` flags, both defaulting to
  `False`, no longer silently implied by the security level.
- **A startup denylist scanner** (`security_check`) that matches known-bad node
  directories, pip pins (for example `ultralytics==8.3.41`), and dropped-file
  artifacts, and force-exits on a hit. This is IOC-based, so it only catches
  already-identified incidents.

Manager is now integrable into core behind `--enable-manager` (core 0.3.76+) and
is enabled by default in the ComfyUI Desktop app and in many prebuilt images.

## 4. Real-world incidents (the validation corpus)

Any scanner's rules should be validated against the attacks that actually
happened. These are the load-bearing cases:

- **ComfyUI_LLMVISION** (June 2024). A node posing as an OpenAI/Anthropic helper
  that installed typosquatted lookalike PyPI packages impersonating `openai` and
  `anthropic`. Those packages ran encoded PowerShell to fetch an info-stealer
  that took browser passwords, card autofill, browsing history, crypto wallet
  data and screenshots, exfiltrated to a Discord webhook. Repo removed after
  disclosure. This plus Ultralytics triggered Comfy Org's Jan 2025 policy
  overhaul.

- **Ultralytics PyPI compromise** (Dec 2024). Not ComfyUI-specific, but pulled in
  by ComfyUI-Impact-Pack and other detection/upscale nodes. A GitHub Actions
  script-injection (malicious PR branch name) poisoned the build for 8.3.41 and
  8.3.42 with an XMRig miner; a later PyPI-credential compromise pushed 8.3.45
  (environment-variable exfiltration) and 8.3.46 (miner). ComfyUI users first
  noticed when Colab instances running Impact-Pack were banned for mining.

- **Upscaler-4K / Akira Stealer** (Oct 2025 to Jan 2026). The canonical
  registry-scanner bypass. Three Registry-published nodes (`upscaler-4k`,
  `lonemilk-upscalernew-4k`, `ComfyUI-Upscaler-4K`) hid the payload in a
  `scripts/` subfolder outside what the automated scan inspected, ran a runtime
  `pip install requests` via subprocess, persisted as a hidden+system
  `AppData/Roaming/DisplayUpdater.exe`, and used a four-layer obfuscation chain
  (Caesar shift, Base64, LZMA, PyArmor) before dropping a Go-based Akira
  info-stealer. Roughly 779 downloads before takedown.

- **Snyk CVE cluster** (Dec 2024). CVE-2024-21574 (Manager pip injection),
  CVE-2024-21575 (Impact-Pack path traversal via `/upload/temp`, write into
  `custom_nodes` then RCE on restart), CVE-2024-21576 (Bmad-Nodes `eval()` with a
  bypassable filter), CVE-2024-21577 (AceNodes `ACE_ExpressionEval` bare
  `eval()`). Snyk also demonstrated that exploiting the AceNodes `eval()` node on
  a hosted platform (Comfy Deploy) leaked live AWS credentials from the container
  environment.

- **Exposed-instance botnets** (GHOST, April 2026; NadMesh, July 2026). Described
  in section 1. These define the "networked and unauthenticated" finding as the
  highest-priority real-world risk, above any individual code CVE.

## 5. Prior art and the gap

Every building block a ComfyUI security suite needs already exists in some
adjacent ecosystem. What does not exist is a ComfyUI-aware tool that assembles
them, understands the node and workflow model, checks live deployment posture,
and reports in standard machine-readable formats.

**Dedicated ComfyUI tools** are all small side projects:

- `christian-byrne/custom-nodes-security-scan`: Bandit plus a large YARA ruleset
  against the node corpus, publishing static HTML reports. The most credible
  community tool (the author is reported to be a Comfy Org engineer), but
  Linux-only, dependent on external binaries, and signature-based.
- `InfiniNode/infininode-advanced-security-pack`: broad feature checklist
  (integrity hashing, YARA, CVE matching, host hardening) but effectively
  unmaintained, with placeholder rules.
- `ComfyNodePRs/PR-comfyui_pt_security_scanner`: an in-ComfyUI node that scans
  `.pt`/`.pth` files with a custom `SafeUnpickler`. Narrow, single format.
- `ashish-aesthisia/Comfy-Spaces` discussion #6: a community RFC for exactly this
  kind of local scanner, with zero engagement. Evidence the gap is recognized
  and unfilled.
- `fabioamigo/ComfyUI-DockerSandbox`: containment, not detection. Complementary.

**The Comfy Registry scanner** is the one gate that operates at scale, but it is
closed-source, centralized, server-side, and after-the-fact. It only covers
registry-published nodes, was bypassed in production (Upscaler-4K), offers no
client-side or offline verification, and does nothing for nodes installed by raw
`git clone`.

**General-purpose engines to build on rather than reinvent:**

- Code SAST: Bandit (AST checks for `eval`/`exec`/`subprocess`/`pickle`/weak
  crypto), Ruff's `flake8-bandit` "S" rules (the same checks, much faster, and
  reportedly what the Registry uses), Semgrep (adds limited taint tracking).
- Dependency SCA: pip-audit and OSV-Scanner (match declared and installed deps
  against OSV and the PyPA Advisory DB), Safety as a second opinion.
- Malicious-package heuristics: GuardDog (Datadog) correlates capability
  (network access) with indicator (suspicious domain) in the same file before
  flagging, which is the design pattern worth copying to cut false positives.
- Model files: `modelscan` (Protect AI, multi-format, denylist), `picklescan`
  (the engine Hugging Face uses, denylist, with a documented
  extension-mismatch bypass in GHSA-jgw4-cr84-mqxg), and Fickling (Trail of
  Bits), whose Sept 2025 scanner flips to an allowlist / provable-safety model
  and is the structurally sound choice for pickle inspection.
- Payload triage: YARA rules (stealer/miner families) and capa (capability
  detection on dropped binaries).
- Secrets: gitleaks (fast regex), TruffleHog (with live verification, used by
  Hugging Face), detect-secrets (entropy plus a baseline-file workflow for
  managing false positives over time).
- Reporting: SARIF 2.1.0 (GitHub code scanning ingests it directly),
  CycloneDX with the ML-BOM extension (a bill of materials for nodes,
  dependencies and model files), CVSS 4.0.

**The gap, stated once:** no actively-maintained, ComfyUI-aware tool spans the
whole surface (node code, dependencies, model files, secrets, live deployment
posture, version-to-CVE matching), understands the node and workflow graph,
runs offline, and emits standard machine-readable output that an automated
remediation agent can consume. Pattern/denylist scanning alone is provably
insufficient: picklescan's extension bypass, Hugging Face's 7z-container bypass,
and Upscaler-4K's obfuscation chain all defeated professionally-maintained
scanners. The design in this repository targets that gap directly.

## 6. Two source-level observations to verify, not yet disclosed CVEs

These came out of direct source review during research and should be treated as
leads, not established findings. The scanner flags them at low confidence and
recommends manual confirmation.

- **`GET /history` may return Comfy.org API keys.** `/prompt` moves
  `SENSITIVE_EXTRA_DATA_KEYS` (`auth_token_comfy_org`, `api_key_comfy_org`) into
  a `sensitive` slot that `/queue` and `/api/jobs` strip, but `/history` and
  `/history/{prompt_id}` return the full record without the equivalent
  stripping. On an exposed instance where a Partner/API node was used, an
  unauthenticated caller may read the key back. No public advisory found.
- **`extra_model_paths.yaml` symlink handling.** ComfyUI does not appear to
  validate that symlink targets inside model directories stay within the
  configured roots, so a symlink planted by a lower-privileged process could
  redirect a "safe" model read to an arbitrary path. Plausible risk class, no
  confirmed bug.

## 7. Note on ComfyUI version numbering

The July 2026 core advisories give the affected range as "< 0.28.0" fixed in
"0.28.0", while the Manager migration for CVE-2025-67303 references core 0.3.76.
These do not sit on the same sequence. The most likely explanation is that the
"ComfyUI (pip)" package is versioned independently from the GitHub tag sequence.
Because of this, the scanner must not decide "vulnerable or not" from a single
version string. It resolves the installed core and Manager identity from package
metadata and the git commit, and matches against advisory data keyed on both,
falling back to a source-level probe (presence of the patched containment logic)
where version data is ambiguous.

## 8. Current ComfyUI security posture (August 2026)

Read from the live repositories (core around v0.31.x). This is the baseline
ComfyHarden aligns to: it recommends enabling what ComfyUI already provides, and
does not flag as vendor bugs the things ComfyUI has already fixed.

Already implemented in core:

- Default bind is `127.0.0.1` (loopback). `--listen` with no value binds all
  interfaces.
- A default origin-only CSRF middleware rejects cross-site requests and Host/Origin
  mismatches. `--enable-cors-header` **replaces** it with a permissive one that
  also sends `Access-Control-Allow-Credentials: true`, so it is a downgrade, not
  just permissive CORS (informs EXP-003).
- A Content-Security-Policy header is emitted only when `--disable-api-nodes` is
  set (informs EXP-007).
- The v0.28.0 release shipped the path-traversal fixes (`LoadImage`,
  `/experiment/models/preview`) and stored-XSS fixes (`/view`, `/userdata`), so
  "core >= 0.28.0, ideally latest" is the highest-value version check
  (informs PATCH-001).
- `SENSITIVE_EXTRA_DATA_KEYS` stripping keeps Comfy.org tokens out of stored
  history; the System User Protection API (`__` prefix, `user/__manager/`) puts
  protected data outside the userdata web API.
- Kill switches: `--disable-all-custom-nodes` (+ `--whitelist-custom-nodes`),
  `--disable-api-nodes`, `--disable-metadata`, `--max-upload-size` (default 100MB).
- Still no built-in authentication (confirmed). `--multi-user` is storage
  partitioning, not access control.
- ComfyUI-Manager is now first-party but opt-in via `--enable-manager`, with
  `--disable-manager-ui` to strip its UI/endpoints on exposed servers.

ComfyUI-Manager: `security_level` (weak/normal-/normal/strong, default normal);
`allow_pip_install`/`allow_git_url_install` default False and take effect only on a
loopback listener; a startup IOC denylist scanner that force-exits on a known-bad
match; and the v3.38 migration of config/snapshots to the protected `user/__manager/`
path (informs HOST-010).

Comfy Registry: publish-time Standards ban `eval`/`exec`, runtime pip install, and
obfuscation; verified publishers via "Claim My Node"; `comfy node validate` runs
Ruff security rules. These are provenance signals ComfyHarden recommends preferring.

Still absent, so they become recommendations rather than assumptions: no built-in
auth (audit the proxy layer), no custom-node signing (so ComfyHarden's hash-based
tamper detection, DRIFT-001/005, is the integrity signal), and no shipped desktop
sandbox (reinforces the containment recommendation).

Sources: `SECURITY.md`, `comfy/cli_args.py`, `server.py`, `app/user_manager.py`,
`folder_paths.py` (Comfy-Org/ComfyUI, master); Comfy-Org/ComfyUI GHSA advisories
(v0.28.0 fixes); Comfy-Org/ComfyUI-Manager (`glob/manager_server.py`,
`glob/security_check.py`, the v3.38 migration doc); docs.comfy.org/registry/standards;
Comfy-Org/comfy-cli (`comfy node validate`).

## 9. Primary sources

Official ComfyUI:

- SECURITY.md, `comfy/cli_args.py`, `server.py`, `execution.py`,
  `app/user_manager.py`, `app/model_manager.py`,
  `api_server/routes/internal/internal_routes.py` (github.com/comfyanonymous/ComfyUI, master)
- github.com/Comfy-Org/ComfyUI/security and .../ComfyUI-Manager/security/advisories
- docs.comfy.org/registry/standards and /registry/overview
- blog.comfy.org: "ComfyUI 2025 Jan Security Update", "Upscaler-4K malicious node pack post", "Meet the new ComfyUI-Manager", "Launching ComfyUI Registry"

Vendor and researcher writeups:

- Snyk Labs, "Hacking ComfyUI Through Custom Nodes"
- Doyensec, "ComfyUI Manager RCE via Custom Node Install" (advisory PDF)
- Tencent Xuanwu Lab (xlab), "Arbitrary File Upload Leading to RCE in ComfyUI-Manager"
- VulnCheck advisory for CVE-2026-68771; ComfyUI PR #14543
- HiddenLayer, Wiz, ReversingLabs, GitGuardian, BleepingComputer on the Ultralytics compromise; PyPI attack analysis blog
- UpGuard, "Detecting Generative AI Data Leaks from ComfyUI"
- Censys and The Hacker News (GHOST); The Hacker News and XLab (NadMesh)
- ComfyUI-Impact-Pack issue #843 (community incident report on the Ultralytics miner)

Tooling and standards:

- Bandit, Ruff (flake8-bandit "S" rules), Semgrep, pip-audit, OSV-Scanner, Safety, GuardDog, Microsoft OSSGadget
- Protect AI modelscan, Trail of Bits Fickling (and its Sept 2025 AI/ML scanner post), mmaitre314 picklescan and GHSA-jgw4-cr84-mqxg, JFrog picklescan zero-day research
- gitleaks, TruffleHog, Yelp detect-secrets
- SARIF 2.1.0 (GitHub code scanning docs), CycloneDX ML-BOM, CVSS 4.0
- Research: SafePickle (arXiv 2602.19818), ShadowPickle (arXiv 2607.17503)

A finding-by-finding URL list is kept alongside the machine-readable ruleset so
that every check carries its own citation. See `spec/checks.example.yaml` for the
format.
