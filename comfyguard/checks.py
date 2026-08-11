"""Checks: read Facts, yield Findings. Read-only and side-effect free.

This is a lean, high-signal subset of the full catalog in docs/CHECKS.md, chosen
to be reliably detectable from a static read of an install plus an optional safe
network probe. Each finding carries its catalog check_id so the report maps back
to the documented catalog.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from . import data
from .models import Finding

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _refs(cid):
    return data.refs(cid)


def _mk(cid, title, category, severity, description, **kw):
    f = Finding(check_id=cid, title=title, category=category, severity=severity,
                description=description, references=_refs(cid), **kw)
    return f.finalize()


def _ver_tuple(v):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:3]) if nums else None


def run_checks(facts: dict, root: Path):
    findings = []
    findings += _exposure(facts)
    findings += _auth(facts)
    findings += _versions(facts)
    findings += _manager_host(facts)
    findings += _ioc(facts)
    findings += _nodes(facts, root)
    findings += _deps(facts)
    findings += _models(facts)
    findings += _secrets(facts, root)
    findings += _network_checks(facts)
    findings += _coverage(facts)
    return findings


def _networked(facts) -> bool:
    flags = facts.get("launch", {}).get("flags", {})
    listen = flags.get("listen")
    non_loopback = listen is True or (isinstance(listen, str) and listen.split(",")[0] not in LOOPBACK)
    net = facts.get("network") or {}
    host = facts.get("host") or {}
    return bool(non_loopback or net.get("reachable") or host.get("publishes_nonloopback_app_port"))


def _fw_note(facts) -> str:
    fw = facts.get("firewall") or {}
    if fw.get("available"):
        return (" Host firewall rules are present; ComfyGuard does not evaluate firewall scope, "
                "so confirm whether inbound to the bind port is restricted (for example to a VPN range).")
    return ""


def _exposure(facts):
    out = []
    launch = facts.get("launch", {})
    flags = launch.get("flags", {})
    src = launch.get("source")
    listen = flags.get("listen")
    non_loopback = listen is True or (isinstance(listen, str) and listen.split(",")[0] not in LOOPBACK)

    if non_loopback:
        val = "0.0.0.0 (all interfaces)" if listen is True else listen
        out.append(_mk(
            "EXP-001", "Bind address is non-loopback", "exposure", "critical",
            "The launch configuration binds a non-loopback address, exposing every unauthenticated endpoint to the network."
            + _fw_note(facts),
            impact="Any network-reachable client can reach /prompt and execute an arbitrary node graph.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "config", "path": src or "launch", "symbol": "--listen"},
            evidence=f"--listen {val} (from {launch.get('source_kind') or 'config'} {src})",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Bind 127.0.0.1 and reach the instance only through an authenticating TLS proxy or VPN.",
                         "action": "Remove the non-loopback --listen (or set 127.0.0.1); front the app with an auth proxy or scope the host firewall.",
                         "rollback": "Restore the prior launch line."}))

    host = facts.get("host") or {}
    if host.get("publishes_nonloopback_app_port") and not non_loopback:
        out.append(_mk(
            "EXP-001", "Docker publishes the ComfyUI port to all interfaces", "exposure", "critical",
            "A docker-compose file publishes the ComfyUI port to a non-loopback host address, so the instance is reachable on the network regardless of the in-container bind."
            + _fw_note(facts),
            impact="Any network-reachable client can reach the API.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "container", "path": host.get("compose_source") or "docker-compose"},
            evidence="; ".join(f"{p.get('host_ip') or '0.0.0.0'}:{p['host_port']}->{p['container_port']}"
                               for p in host.get("published_app_ports", []) if p.get("nonloopback")),
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Publish to 127.0.0.1 only, and reach the instance through an authenticating proxy.",
                         "action": "Prefix the compose port mapping with 127.0.0.1, or remove the published port.",
                         "rollback": "Restore the prior compose ports."}))

    if src is None and not facts.get("network") and not host.get("publishes_nonloopback_app_port"):
        # Fail-safe: could not determine the bind configuration, so do not let the
        # pre-exposure gate pass silently.
        out.append(_mk(
            "EXP-000", "Exposure could not be determined", "exposure", "medium",
            "No launch configuration or running process was found, so ComfyGuard could not confirm the bind address. "
            "Silence here is not evidence of safety.",
            impact="The instance may be network-exposed without any finding to flag it.",
            confidence="medium", urgency="blocker", decision_owner="human",
            location={"kind": "config", "path": facts.get("comfy_root", "")},
            evidence="no launcher, systemd unit, compose file, or matching running process found",
            remediation={"class": "manual", "gate": "review-required",
                         "summary": "Confirm the bind address manually, or pass --launch-file / --launch-dir, or probe with --url --authorized.",
                         "action": "Check how the instance is started and whether it binds a non-loopback address.",
                         "rollback": "N/A"}))

    if "enable_cors_header" in flags:
        out.append(_mk(
            "EXP-003", "Permissive CORS disables the built-in Origin check", "exposure", "high",
            "--enable-cors-header replaces ComfyUI's default origin-only CSRF middleware with a permissive one, removing the built-in anti-CSRF and anti-DNS-rebinding guard.",
            impact="A website the operator's browser visits can script the instance cross-origin.",
            confidence="high", urgency="urgent",
            location={"kind": "config", "path": src or "launch", "symbol": "--enable-cors-header"},
            evidence="--enable-cors-header is set",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Remove --enable-cors-header unless one specific origin truly needs it.",
                         "action": "Drop the flag, or scope it to a single origin.",
                         "rollback": "Re-add the flag."}))

    has_tls = "tls_keyfile" in flags and "tls_certfile" in flags
    if non_loopback and not has_tls:
        out.append(_mk(
            "EXP-004", "No TLS on a non-loopback listener", "exposure", "high",
            "The instance binds a non-loopback address with no --tls-keyfile/--tls-certfile. Unless a TLS-terminating proxy is in front, traffic (including any API keys) is plaintext.",
            impact="Credentials and workflow content travel in clear text on the network.",
            confidence="medium", urgency="urgent",
            location={"kind": "config", "path": src or "launch"},
            evidence="non-loopback --listen and no --tls-* flags",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Terminate TLS at a reverse proxy, or set --tls-keyfile/--tls-certfile.",
                         "action": "Add TLS at the proxy or via the core flags.",
                         "rollback": "N/A"}))
    return out


def _auth(facts):
    out = []
    if _networked(facts):
        out.append(_mk(
            "AUTH-001", "No authenticating layer on a networked instance", "authentication", "critical",
            "ComfyUI core has no authentication. On a networked instance, auth must come from a reverse proxy or VPN. None was detected."
            + _fw_note(facts),
            impact="Every endpoint, including /prompt (arbitrary code execution) and /ws, is open to anyone who can reach it.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "config", "path": "core"},
            evidence="core has no auth; no proxy auth signature detected",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Put an authenticating, TLS-terminating proxy (nginx/Caddy/Cloudflare Access) in front, or keep it on a private network.",
                         "action": "Add an auth proxy; treat --multi-user as storage partitioning, not auth.",
                         "rollback": "Remote users must authenticate from now on."}))
    return out


def _versions(facts):
    out = []
    core_v = facts.get("core", {}).get("version")
    t = _ver_tuple(core_v)
    if t:
        major = t[0]
        minor = t[1] if len(t) > 1 else 0
        # Modern scheme (0.10+): a numeric compare is meaningful.
        if major == 0 and minor >= 10 and t < (0, 28, 0):
            out.append(_mk(
                "PATCH-001", "Core version predates the 0.28.0 security fixes", "known-vulnerable-version", "high",
                "The core version is below 0.28.0, which shipped the path-traversal and stored-XSS fixes (CVE-2026-56670/56672/56673).",
                impact="Unauthenticated file-existence probing, limited file read, and token-stealing XSS when networked.",
                confidence="medium", urgency="urgent",
                location={"kind": "config", "path": "core", "symbol": f"version {core_v}"},
                evidence=f"core version {core_v} < 0.28.0",
                remediation={"class": "upgrade", "gate": "review-required",
                             "summary": "Upgrade core to the latest release and smoke-test workflows first.",
                             "action": "Update ComfyUI core; test in a safe environment before production.",
                             "rollback": "Pin the prior commit if a workflow regresses."}))
        elif major == 0 and 0 < minor < 10:
            # 0.1.x-0.9.x (and the ambiguous 0.3.x historical scheme): do not assert
            # vulnerable numerically. Recommend a manual check instead of a false positive.
            out.append(_mk(
                "PATCH-001", "Confirm core is at or above the 0.28.0 security fixes", "known-vulnerable-version", "info",
                "ComfyGuard cannot reliably compare this version numerically against 0.28.0 because ComfyUI's version scheme is ambiguous in this range. Verify by release date or commit that the July 2026 fixes are present.",
                impact="Undetermined; verify manually.",
                confidence="low", urgency="hardening",
                location={"kind": "config", "path": "core", "symbol": f"version {core_v}"},
                evidence=f"core version {core_v}; numeric comparison unreliable in this range",
                remediation={"class": "manual", "gate": "review-required",
                             "summary": "Confirm the core release date or commit is at or after the 0.28.0 fixes.",
                             "action": "Check the changelog/commit; upgrade if older.",
                             "rollback": "N/A"}))
    mgr = facts.get("manager", {})
    mv = _ver_tuple(mgr.get("version"))
    if mgr.get("present") and mv is not None and mv < (3, 38):
        out.append(_mk(
            "PATCH-003", "ComfyUI-Manager below 3.38 (config-exposure RCE)", "known-vulnerable-version", "high",
            "Manager below 3.38 stores config where the core web API can reach it (CVE-2025-67303), so an unauthenticated attacker can downgrade the security level and reach RCE.",
            impact="Remote code execution on a networked instance.",
            confidence="high", urgency="urgent",
            location={"kind": "config", "path": mgr.get("dir") or "custom_nodes/ComfyUI-Manager", "symbol": f"version {mgr.get('version')}"},
            evidence=f"Manager version {mgr.get('version')} < 3.38",
            remediation={"class": "upgrade", "gate": "review-required",
                         "summary": "Upgrade Manager to 3.38+ (and core to the version supporting the protected path), then run the userdata migration.",
                         "action": "Back up user/ first; update Manager and core.",
                         "rollback": "Keep the user/ backup and prior versions pinned."}))
    return out


def _manager_host(facts):
    out = []
    mgr = facts.get("manager", {})
    networked = _networked(facts)
    if mgr.get("present"):
        lvl = (mgr.get("security_level") or "").lower()
        nm = mgr.get("network_mode")
        bs = mgr.get("bypass_ssl")
        fire, sev, why = False, "medium", []
        if lvl in ("weak", "normal-"):
            fire, sev = True, "high"
            why.append(f"security_level={mgr.get('security_level')}")
        elif lvl == "normal" and networked:
            fire, sev = True, "medium"
            why.append("security_level=normal on a networked instance (best practice is strong)")
        if mgr.get("allow_pip_install") or mgr.get("allow_git_url_install"):
            fire, sev = True, "high"
            why.append("runtime install flags enabled")
        if bs:
            fire = True
            sev = "high" if sev == "high" else "medium"
            why.append("bypass_ssl=True (TLS verification disabled for downloads)")
        if fire:
            ev = "; ".join(why)
            if nm:
                ev += f"; network_mode={nm}" + (" (mitigating)" if str(nm).lower() == "offline" else "")
            out.append(_mk(
                "HOST-007", "ComfyUI-Manager configured below the recommended baseline", "host", sev,
                "The Manager configuration is weaker than the recommended baseline for a networked instance.",
                impact="Widens the Manager install/RCE surface, or weakens download integrity.",
                confidence="high", urgency="urgent" if sev == "high" else "standard",
                location={"kind": "config", "path": mgr.get("config_path") or "config.ini", "symbol": "security_level"},
                evidence=ev,
                remediation={"class": "config", "gate": "review-required",
                             "summary": "Set security_level=strong on a networked instance and disable bypass_ssl.",
                             "action": "Edit config.ini accordingly.",
                             "rollback": "Restore the prior config.ini."}))
        if mgr.get("config_path_is_legacy"):
            out.append(_mk(
                "HOST-010", "Manager config on the legacy web-reachable path", "host", "high",
                "Manager config sits under user/default/ (pre-__manager migration), reachable through the core web API and tamperable remotely.",
                impact="Remote config tampering can downgrade security or redirect the node channel.",
                confidence="high", urgency="urgent",
                location={"kind": "config", "path": mgr.get("config_path")},
                evidence="config under user/default/ComfyUI-Manager/ rather than user/__manager/",
                remediation={"class": "upgrade", "gate": "review-required",
                             "summary": "Upgrade Manager (3.38+) and core so the config moves to the protected user/__manager/ path.",
                             "action": "Update and run the userdata migration.",
                             "rollback": "Keep a backup of user/."}))
    host = facts.get("host", {})
    if host.get("docker_user") in (None, "root", "0") and host.get("docker_user_source"):
        du = host.get("docker_user")
        out.append(_mk(
            "HOST-001", "Container runs as root", "host", "high",
            "The container has no non-root USER (or USER is root), maximizing the blast radius of any node-level code execution.",
            impact="A node RCE becomes host-root-equivalent inside the container.",
            confidence="medium", urgency="standard",
            location={"kind": "container", "path": host.get("docker_user_source") or "Dockerfile", "symbol": f"USER {du}"},
            evidence=f"USER={du!r}",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Add a non-root USER with a fixed UID/GID.",
                         "action": "Add a comfy user in the Dockerfile and set USER.",
                         "rollback": "Remove the USER directive."}))
    for kind, key in (("custom_nodes", "custom_nodes_writable"), ("models", "models_writable")):
        if host.get(key) is True:
            out.append(_mk(
                "HOST-006", f"{kind} directory is group- or world-writable", "host", "medium",
                f"The {kind} directory is writable beyond its owner, so a lower-privileged user could plant code that loads at startup.",
                impact="Local privilege path into the ComfyUI process.",
                confidence="high", urgency="standard",
                location={"kind": "config", "path": kind},
                evidence="group/other write bit set",
                remediation={"class": "config", "gate": "review-required",
                             "summary": "Tighten permissions so only the service account can write.",
                             "action": "Restrict group/other write on the directory.",
                             "rollback": "Restore prior permissions."}))
    if host.get("exposed_ports") or host.get("mounts_docker_socket"):
        ev = []
        if host.get("mounts_docker_socket"):
            ev.append("/var/run/docker.sock mounted")
        if host.get("exposed_ports"):
            ev.append("ports " + ", ".join(sorted(set(host["exposed_ports"]))))
        out.append(_mk(
            "HOST-014", "Lateral-movement service reachable", "host", "critical",
            "A Docker daemon (2375) or a Redis/other backend (6379) is exposed, or the Docker socket is mounted. These are the exact escape and persistence vectors used by the 2026 botnets.",
            impact="Container escape and host compromise.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "container", "path": "docker-compose"},
            evidence="; ".join(ev),
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Never expose the Docker socket or TCP 2375; require auth and bind backends to loopback.",
                         "action": "Remove the mount/port exposure; firewall the backend.",
                         "rollback": "N/A"}))
    if host.get("privileged"):
        out.append(_mk(
            "HOST-002", "Container runs privileged", "host", "critical",
            "The container is marked privileged, which removes most isolation and is unnecessary for ComfyUI.",
            impact="Trivial container escape to the host.",
            confidence="high", urgency="blocker",
            location={"kind": "container", "path": "docker-compose", "symbol": "privileged: true"},
            evidence="privileged: true",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Remove privileged; grant only scoped GPU device access.",
                         "action": "Drop privileged: true; use the NVIDIA device mechanism.",
                         "rollback": "N/A"}))
    return out


def _ioc(facts):
    out = []
    ioc = facts.get("ioc", {})
    for path in ioc.get("host_artifacts", []):
        out.append(_mk(
            "IOC-001", "Host compromise indicator present", "ioc", "critical",
            "A host-level artifact associated with the 2026 ComfyUI botnet was found (for example an LD_PRELOAD rootkit hook).",
            impact="Strong sign the host is already compromised.",
            confidence="medium", urgency="blocker", decision_owner="human",
            location={"kind": "process", "path": path}, evidence=f"{path} exists",
            remediation={"class": "manual", "gate": "human-only",
                         "summary": "Take the instance offline and investigate. Do not just delete the artifact.",
                         "action": "Isolate the host; involve incident response.", "rollback": "N/A"}))
    for node in ioc.get("malicious_nodes", []):
        out.append(_mk(
            "PATCH-007", "Known-malicious custom node present", "known-vulnerable-version", "critical",
            "A custom node directory matches a known info-stealer or botnet campaign.",
            impact="Credential/wallet theft, persistence, and exfiltration when the node loads.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "file", "path": node},
            evidence=f"node directory {node} matches the malicious-node feed",
            remediation={"class": "quarantine", "gate": "review-required",
                         "summary": "Quarantine the node (move aside, do not delete) and treat the host as possibly compromised.",
                         "action": "Move the directory to quarantine; investigate persistence artifacts.",
                         "rollback": "Restore only if confirmed a false positive."}))
    for pin in ioc.get("bad_pins", []):
        out.append(_mk(
            "IOC-006", "Known-malicious dependency pin declared", "ioc", "critical",
            "A declared dependency matches a known supply-chain-compromised release.",
            impact="Cryptominer or credential stealer pulled in at install.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "dependency", "path": "requirements.txt", "symbol": pin}, evidence=pin,
            remediation={"class": "quarantine", "gate": "review-required",
                         "summary": "Remove the pin, reinstall a clean version, and check for miner artifacts.",
                         "action": "Pin a known-good version; audit the environment.", "rollback": "N/A"}))
    if ioc.get("poisoned_workflow"):
        out.append(_mk(
            "IOC-004", "Auto-run workflow contains a payload fetch", "ioc", "critical",
            "The default auto-run workflow references a shell/download/exec payload, matching the botnet persistence pattern.",
            impact="Payload re-runs on restart.",
            confidence="medium", urgency="blocker", decision_owner="human",
            location={"kind": "file", "path": ioc["poisoned_workflow"]},
            evidence="curl/wget/urllib/exec reference in default.json",
            remediation={"class": "quarantine", "gate": "review-required",
                         "summary": "Quarantine the workflow and treat the host as possibly compromised.",
                         "action": "Move the file aside; investigate.", "rollback": "Restore only if confirmed benign."}))
    return out


# ---------- custom-node static analysis ----------

DECODER_NAMES = {"b64decode", "b16decode", "b32decode", "a85decode", "decompress", "decode", "loads"}


def _call_name(func) -> str:
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _literal_strings(node):
    return [s.value for s in ast.walk(node) if isinstance(s, ast.Constant) and isinstance(s.value, str)]


class _Scanner(ast.NodeVisitor):
    def __init__(self):
        self.hits = []
        self.depth = 0

    def _fn(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = _fn
    visit_AsyncFunctionDef = _fn
    visit_Lambda = _fn

    def _add(self, cid, line, evidence):
        if len(self.hits) < 40:
            self.hits.append((cid, line, evidence[:200], self.depth == 0))

    def visit_Call(self, node):
        name = _call_name(node.func)
        base = name.split(".")[-1]
        strings = " ".join(_literal_strings(node))
        # builtin eval/exec ONLY when the call target is a bare name (T2):
        # this excludes model.eval(), df.eval(), etc.
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            decoders = any(isinstance(a, ast.Call) and _call_name(a.func).split(".")[-1] in DECODER_NAMES for a in node.args)
            const_only = node.args and all(isinstance(a, ast.Constant) for a in node.args)
            if decoders:
                self._add("NODE-004", node.lineno, f"{node.func.id}() on decoded/obfuscated data")
            else:
                self._add("NODE-001", node.lineno, f"{node.func.id}() call" + (" (constant arg)" if const_only else ""))
        if name == "os.system":
            self._add("NODE-002", node.lineno, "os.system(...)")
        if name.startswith("subprocess.") or (base in ("Popen", "check_output", "check_call") and "subprocess" in name):
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            if re.search(r"\bpip\b", strings) and "install" in strings:
                self._add("NODE-003", node.lineno, "subprocess pip install at runtime")
            elif shell_true:
                self._add("NODE-002", node.lineno, "subprocess with shell=True")
            elif not (node.args and isinstance(node.args[0], (ast.List, ast.Constant))):
                self._add("NODE-002", node.lineno, "subprocess with a dynamic command")
        if name in ("pip.main", "pip._internal.main"):
            self._add("NODE-003", node.lineno, "pip.main(...) at runtime")
        if name in ("pickle.load", "pickle.loads", "marshal.loads", "dill.load", "dill.loads", "_pickle.load", "_pickle.loads"):
            self._add("NODE-010", node.lineno, f"{name}(...) untrusted deserialization")
        if base == "load" and name.endswith("torch.load"):
            wo = any(k.arg == "weights_only" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            if not wo:
                self._add("NODE-010", node.lineno, "torch.load(...) without weights_only=True")
        if name.startswith("requests.") or name.startswith("httpx.") or base == "urlopen":
            for marker in data.SUSPICIOUS_NET_MARKERS + data.IOC_C2:
                if marker in strings:
                    self._add("NODE-006", node.lineno, f"network call to {marker}")
                    break
            else:
                if data.IP_LITERAL.search(strings):
                    self._add("NODE-006", node.lineno, "network call to a hardcoded IP")
        self.generic_visit(node)


def _scan_python(text: str):
    try:
        tree = ast.parse(text)
    except Exception:
        return None  # unparseable (syntax error / Py2); distinct from "no hits"
    sc = _Scanner()
    sc.visit(tree)
    return sc.hits


NODE_META = {
    "NODE-001": ("eval/exec in custom node", "high", "Arbitrary Python execution when the node runs."),
    "NODE-002": ("Shell or dynamic subprocess in custom node", "high", "Command execution surface."),
    "NODE-003": ("Runtime package install in custom node", "high", "Uncontrolled dependency fetch and code execution."),
    "NODE-004": ("Obfuscated code execution in custom node", "high", "Decoded-then-executed payload, a malware pattern."),
    "NODE-006": ("Exfiltration-shaped network call in custom node", "high", "Possible data exfiltration when the node runs."),
    "NODE-007": ("Custom node reads credential locations", "critical", "Stealer-shaped behavior."),
    "NODE-010": ("Unsafe deserialization in custom node", "high", "Code execution on load of crafted data."),
    "NODE-011": ("install.py performs risky actions", "high", "Runs at install time, before any review."),
}
NODE_REMEDIATION = {
    "class": "manual", "gate": "review-required",
    "summary": "Review the node's intent; remove or gate the behavior, and prefer a trusted alternative.",
    "action": "Inspect the flagged code; confirm what it does and whether it is needed.",
    "rollback": "Revert the node file.",
}
CRED_RE = re.compile(r"(\.aws|\.ssh/|Login Data|wallet\.dat|cookies\.sqlite|/\.config/google-chrome)", re.I)


def _nodes(facts, root: Path):
    out = []
    unparsed = 0
    for node in facts.get("nodes", []):
        if node.get("disabled"):
            continue
        for pyabs in node.get("py_files", []):
            p = Path(pyabs)
            try:
                rel = str(p.relative_to(root))
            except Exception:
                rel = pyabs
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            is_install = p.name == "install.py"
            m = CRED_RE.search(text)
            if m:
                out.append(_finding_node("NODE-007", rel, _line_of(text, m.start()), m.group(0), False))
            hits = _scan_python(text)
            if hits is None:
                unparsed += 1
                continue
            for cid, line, evidence, toplevel in hits:
                use_cid = "NODE-011" if is_install else cid
                out.append(_finding_node(use_cid, rel, line, evidence, toplevel or is_install))
    if unparsed:
        out.append(_mk(
            "SCAN-002", "Some custom-node files could not be parsed", "coverage", "info",
            "One or more Python files failed to parse (syntax error or Python 2) and were not statically analyzed, so a finding could have been missed in them.",
            impact="Reduced coverage.", confidence="high", urgency="hardening",
            location={"kind": "config", "path": "custom_nodes"},
            evidence=f"{unparsed} file(s) unparsed",
            remediation={"class": "manual", "gate": "review-required",
                         "summary": "Review the unparseable files manually if the packs are untrusted.",
                         "action": "Open the affected files.", "rollback": "N/A"}))
    return out


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _finding_node(cid, rel, line, evidence, toplevel):
    title, severity, impact = NODE_META.get(cid, NODE_META["NODE-001"])
    urgency = "urgent" if toplevel else "standard"
    note = " (runs at import/startup)" if toplevel and cid != "NODE-011" else ""
    dec = "human" if cid == "NODE-007" else "agent"
    return _mk(cid, title, "custom-node-code", severity,
               f"{title}.{note}".strip(), impact=impact, confidence="medium",
               urgency=urgency, decision_owner=dec,
               location={"kind": "file", "path": rel, "line": line},
               evidence=evidence, remediation=dict(NODE_REMEDIATION))


def _deps(facts):
    out = []
    for d in facts.get("deps", {}).get("declared", []):
        if d.get("url"):
            out.append(_mk(
                "DEP-003", "Dependency installed from a direct URL or git", "dependency", "medium",
                "A requirement is a direct URL or git reference rather than a pinned PyPI package, bypassing normal review.",
                impact="Supply-chain exposure; the target can change.", confidence="high", urgency="standard",
                location={"kind": "dependency", "path": d.get("declared_in", "requirements.txt"), "symbol": d["name"]},
                evidence=d["raw"],
                remediation={"class": "manual", "gate": "review-required",
                             "summary": "Prefer a pinned PyPI release from a trusted source.",
                             "action": "Replace with a pinned package where possible.", "rollback": "N/A"}))
        elif not d.get("pinned"):
            out.append(_mk(
                "DEP-002", "Unpinned dependency", "dependency", "low",
                "A dependency has no exact version pin, so a future compromised release can be pulled in.",
                impact="Supply-chain exposure at the next install or update.", confidence="high", urgency="hardening",
                location={"kind": "dependency", "path": d.get("declared_in", "requirements.txt"), "symbol": d["name"]},
                evidence=d["raw"],
                remediation={"class": "config", "gate": "review-required",
                             "summary": "Pin the dependency to a known-good version.",
                             "action": f"Set {d['name']}==<version>.", "rollback": "Remove the pin."}))
    return out


def _models(facts):
    files = facts.get("models", {}).get("files", [])
    pickles = [f for f in files if f.get("pickle")]
    if not pickles:
        return []
    sample = ", ".join(f["path"] for f in pickles[:5])
    more = "" if len(pickles) <= 5 else f" (+{len(pickles) - 5} more)"
    return [_mk(
        "MODEL-001", "Pickle-format model files present", "model-file", "info",
        "One or more models use a pickle-bearing format (.ckpt/.pt/.pth/.bin/.pkl), which can execute code when loaded. Treat any from an untrusted source as code, not data.",
        impact="Code execution on load if a file is malicious. Full opcode scanning is a later phase.",
        confidence="high", urgency="standard", location={"kind": "model", "path": "models"},
        evidence=f"{len(pickles)} pickle-format model file(s): {sample}{more}",
        remediation={"class": "manual", "gate": "review-required",
                     "summary": "Prefer safetensors; verify the provenance of any pickle-format model.",
                     "action": "Replace untrusted pickle models with safetensors equivalents.", "rollback": "N/A"})]


def _secrets(facts, root: Path):
    out = []
    seen = 0
    candidates = []
    src = facts.get("launch", {}).get("source")
    if src and (root / src).exists():
        candidates.append(root / src)
    for extra in (".env", "user/__manager/config.ini", "user/default/ComfyUI-Manager/config.ini"):
        p = root / extra
        if p.exists():
            candidates.append(p)
    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for rx in data.SECRET_VALUE_PATTERNS:
            m = rx.search(text)
            if m and seen < 10:
                seen += 1
                rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
                out.append(_mk(
                    "SEC-004", "Possible secret in a config or launch file", "secret", "high",
                    "A value matching a credential shape was found in a config or launch file. If real, it may be readable by more parties than intended.",
                    impact="Credential exposure.", confidence="medium", urgency="urgent", decision_owner="human",
                    location={"kind": "file", "path": rel, "line": _line_of(text, m.start())},
                    evidence="[redacted secret-shaped value]",
                    remediation={"class": "secret", "gate": "human-only",
                                 "summary": "Move the secret to a mounted file or a secrets manager, and rotate it.",
                                 "action": "Relocate the credential; the owner rotates it.", "rollback": "N/A"}))
    return out


def _network_checks(facts):
    out = []
    net = facts.get("network")
    if not net or not net.get("reachable"):
        return out
    if net.get("status") == 200 and not net.get("auth_challenge"):
        out.append(_mk(
            "EXP-002", "ComfyUI reachable with no authenticating layer", "exposure", "critical",
            "GET /system_stats returned 200 with no auth challenge, so the API answers unauthenticated requests.",
            impact="Any reachable client can submit workflows via /prompt and execute code.",
            confidence="high", urgency="blocker", decision_owner="human",
            location={"kind": "endpoint", "path": "GET /system_stats"}, evidence="HTTP 200, no WWW-Authenticate",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Front the instance with an authenticating TLS proxy or move it to a private network.",
                         "action": "Add auth in front of the whole app.", "rollback": "N/A"}))
    if net.get("cors") == "*":
        out.append(_mk(
            "EXP-003", "Permissive CORS header observed", "exposure", "high",
            "The instance returns Access-Control-Allow-Origin: *, which disables the built-in Origin/CSRF check.",
            impact="Cross-origin scripting of the instance from any website.", confidence="high", urgency="urgent",
            location={"kind": "endpoint", "path": "response header"}, evidence="Access-Control-Allow-Origin: *",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Remove --enable-cors-header or scope it to one origin.",
                         "action": "Drop or narrow the CORS flag.", "rollback": "N/A"}))
    # T4: plaintext HTTP on a loopback probe is expected, not a finding.
    if not net.get("https") and not net.get("loopback"):
        out.append(_mk(
            "EXP-004", "Instance answered over plain HTTP", "exposure", "high",
            "The probed URL is plain HTTP on a non-loopback host, so traffic is not encrypted in transit.",
            impact="Credentials and content are visible on the network path.", confidence="medium", urgency="urgent",
            location={"kind": "endpoint", "path": net.get("url", "")}, evidence="http:// scheme, non-loopback host, reachable",
            remediation={"class": "config", "gate": "review-required",
                         "summary": "Terminate TLS at the proxy or via core TLS flags.",
                         "action": "Serve over HTTPS.", "rollback": "N/A"}))
    return out


def _coverage(facts):
    """T6: disclose truncated node packs so a truncated pack is not mistaken for a
    clean one."""
    truncated = [f"{n['name']} ({n['files_scanned']}/{n['files_total']})"
                 for n in facts.get("nodes", [])
                 if not n.get("disabled") and n.get("files_total", 0) > n.get("files_scanned", 0)]
    if not truncated:
        return []
    return [_mk(
        "SCAN-001", "Some custom-node packs were only partially scanned", "coverage", "info",
        "One or more packs have more Python files than the per-pack scan cap, so static analysis did not read all of them. Absence of a finding in these packs is not proof they are clean.",
        impact="Reduced coverage in the listed packs.", confidence="high", urgency="hardening",
        location={"kind": "config", "path": "custom_nodes"},
        evidence="truncated: " + "; ".join(truncated[:10]) + ("" if len(truncated) <= 10 else f" (+{len(truncated)-10} more)"),
        remediation={"class": "manual", "gate": "review-required",
                     "summary": "Review the large packs manually, or raise the scan cap.",
                     "action": "Inspect the entrypoints of the listed packs.", "rollback": "N/A"})]
