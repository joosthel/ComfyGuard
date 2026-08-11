"""Read-only collectors. They only read from the install and, optionally, make
safe GET probes against an authorized URL. They never modify anything."""

from __future__ import annotations

import configparser
import os
import re
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

LAUNCH_FLAG_RE = {
    "listen": re.compile(r"--listen(?:[=\s]+([^\s\"']+))?"),
    "port": re.compile(r"--port(?:[=\s]+(\d+))?"),
    "enable_cors_header": re.compile(r"--enable-cors-header(?:[=\s]+([^\s\"']+))?"),
    "tls_keyfile": re.compile(r"--tls-keyfile(?:[=\s]+([^\s\"']+))?"),
    "tls_certfile": re.compile(r"--tls-certfile(?:[=\s]+([^\s\"']+))?"),
    "disable_api_nodes": re.compile(r"--disable-api-nodes"),
    "disable_metadata": re.compile(r"--disable-metadata"),
    "disable_all_custom_nodes": re.compile(r"--disable-all-custom-nodes"),
    "enable_manager": re.compile(r"--enable-manager"),
    "disable_manager_ui": re.compile(r"--disable-manager-ui"),
    "max_upload_size": re.compile(r"--max-upload-size(?:[=\s]+([\d.]+))?"),
}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "loopback"}
LAUNCH_GLOBS = ["*.sh", "*.bat", "*.cmd", "*.service", "*.conf", "Dockerfile",
                "docker-compose*.yml", "docker-compose*.yaml"]
LAUNCH_SUBDIRS = ["advanced", "deploy", "scripts", "bin"]
SKIP_NODE_DIRS = {"__pycache__", "logs", ".git"}
SKIP_PACK_SUBDIRS = {"tests", "test", "examples", "example", "docs", "doc", "__pycache__", ".git"}
ENTRYPOINT_ORDER = {"__init__.py": 0, "install.py": 1, "prestartup_script.py": 2, "nodes.py": 3}

MAX_NODE_PY = 400          # cap python files scanned per pack (raised; dead code is skipped)
MAX_FILE_BYTES = 1_500_000
MAX_MODELS = 4000


def looks_like_comfyui(root: Path) -> bool:
    return any((root / p).exists() for p in ("main.py", "comfy", "custom_nodes", "nodes.py", "comfyui_version.py"))


def _resolve_comfy_root(root: Path) -> Path:
    """The directory that actually holds main.py/custom_nodes. Descends into a
    ComfyUI/ subdir for the windows-portable layout when pointed at the root."""
    if looks_like_comfyui(root):
        return root
    for sub in ("ComfyUI", "comfyui"):
        if (root / sub).exists() and looks_like_comfyui(root / sub):
            return root / sub
    return root


def _is_portable_dir(d: Path) -> bool:
    try:
        return (d / "python_embeded").exists() or (d / "python_embedded").exists() \
            or bool(list(d.glob("run_*.bat"))) or (d / "ComfyUI").exists()
    except Exception:
        return False


def _run(cmd, cwd=None, timeout=8):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def _git_info(d: Path) -> dict:
    if not (d / ".git").exists():
        return {"is_git": False}
    info = {"is_git": True}
    info["commit"] = _run(["git", "rev-parse", "HEAD"], cwd=d)
    info["branch"] = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=d)
    info["remote"] = _run(["git", "config", "--get", "remote.origin.url"], cwd=d)
    status = _run(["git", "status", "--porcelain"], cwd=d)
    info["dirty"] = bool(status) if status is not None else None
    return info


def _read(p: Path, limit=MAX_FILE_BYTES) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _world_or_group_writable(p: Path):
    # POSIX-only. On Windows the mode bits are synthesized (0o777) and meaningless,
    # so return None (check not applicable) rather than a false positive.
    if os.name == "nt":
        return None
    try:
        return bool(p.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    except Exception:
        return None


def _is_nonloopback(listen):
    return listen is True or (isinstance(listen, str) and listen.split(",")[0] not in LOOPBACK)


def collect(root, url=None, authorized=False, launch_file=None, launch_dir=None) -> dict:
    root = Path(root).expanduser().resolve()
    comfy_root = _resolve_comfy_root(root)
    facts = {
        "root": str(root),
        "comfy_root": str(comfy_root),
        "is_comfyui": looks_like_comfyui(comfy_root),
        "scanner": {"uid": os.geteuid() if hasattr(os, "geteuid") else None, "platform": os.name},
    }
    facts["core"] = _core(comfy_root)
    facts["launch"] = _launch(comfy_root, root, launch_file, launch_dir)
    facts["manager"] = _manager(comfy_root)
    facts["nodes"] = _nodes(comfy_root)
    facts["deps"] = _deps(comfy_root, facts["nodes"])
    facts["models"] = _models(comfy_root)
    facts["host"] = _host(comfy_root)
    facts["ioc"] = _ioc(comfy_root, facts["nodes"], facts["deps"])
    facts["firewall"] = _firewall()
    facts["network"] = _network(url) if (url and authorized) else None
    return facts


def _core(root: Path) -> dict:
    core = {"version": None, **_git_info(root)}
    vf = root / "comfyui_version.py"
    if vf.exists():
        m = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)', _read(vf))
        if m:
            core["version"] = m.group(1)
    return core


# ---------- launch detection (T1) ----------

def _extract_flags(text: str) -> dict:
    flags = {}
    for name, rx in LAUNCH_FLAG_RE.items():
        m = rx.search(text)
        if m:
            flags[name] = m.group(1) if m.groups() and m.group(1) is not None else True
    return flags


def _launch_candidate_dirs(comfy_root: Path, audit_root: Path):
    dirs = []
    seen = set()

    def add(d):
        try:
            d = d.resolve()
        except Exception:
            return
        if d not in seen and d.exists():
            seen.add(d)
            dirs.append(d)

    add(comfy_root)
    add(audit_root)
    # portable / parent layouts: search up to two levels up
    for up in (comfy_root.parent, comfy_root.parent.parent):
        if _is_portable_dir(up):
            add(up)
    add(audit_root.parent)
    return dirs


def _iter_launch_files(comfy_root: Path, audit_root: Path, launch_file, launch_dir):
    if launch_file:
        p = Path(launch_file).expanduser()
        if p.exists():
            yield p
    search_dirs = []
    if launch_dir:
        search_dirs.append(Path(launch_dir).expanduser())
    search_dirs += _launch_candidate_dirs(comfy_root, audit_root)
    yielded = set()
    for d in search_dirs:
        globs = list(LAUNCH_GLOBS)
        for sub in LAUNCH_SUBDIRS:
            globs += [f"{sub}/{g}" for g in LAUNCH_GLOBS]
        for pat in globs:
            for p in d.glob(pat):
                if p.is_file() and p not in yielded:
                    yielded.add(p)
                    yield p


def _parse_launch_file(p: Path, comfy_root: Path):
    text = _read(p)
    for line in text.splitlines():
        low = line.lower()
        if "main.py" not in low and "comfyui" not in low:
            continue
        if "--" not in line:
            continue
        flags = _extract_flags(line)
        if flags:
            src = str(p)
            try:
                src = str(p.relative_to(comfy_root))
            except Exception:
                try:
                    src = str(p.relative_to(comfy_root.parent))
                except Exception:
                    pass
            return {"source": src, "source_kind": "file", "flags": flags, "raw": line.strip()[:300]}
    return None


def _launch(comfy_root: Path, audit_root: Path, launch_file=None, launch_dir=None) -> dict:
    # 1. running process is ground truth (best-effort, cross-platform)
    proc = _process_launch(comfy_root)
    if proc:
        return proc
    # 2. launcher files across the install, its portable parent, and subfolders
    best = None
    for p in _iter_launch_files(comfy_root, audit_root, launch_file, launch_dir):
        parsed = _parse_launch_file(p, comfy_root)
        if not parsed:
            continue
        if best is None:
            best = parsed
        # a launcher that binds a non-loopback address is the risk to report
        if _is_nonloopback(parsed["flags"].get("listen")):
            return parsed
    if best is not None:
        return best
    return {"source": None, "source_kind": None, "flags": {}, "raw": None}


def _python_procs():
    """Best-effort list of (pid, cmdline, image_path) for python processes."""
    procs = []
    try:
        if os.name == "nt":
            out = _run(["powershell", "-NoProfile", "-Command",
                        "Get-CimInstance Win32_Process -Filter \"Name like '%python%'\" | "
                        "ForEach-Object { \"$($_.ProcessId)`t$($_.ExecutablePath)`t$($_.CommandLine)\" }"], timeout=10)
            if out:
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        procs.append((parts[0].strip(), parts[2], parts[1].strip()))
        else:
            out = _run(["ps", "-axww", "-o", "pid=,args="], timeout=10)
            if out:
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    pid, _, args = line.partition(" ")
                    if "python" in args.lower() or "main.py" in args:
                        image = args.split()[0] if args.split() else ""
                        procs.append((pid, args, image))
    except Exception:
        return []
    return procs


def _under(root: Path, path: str) -> bool:
    try:
        p = Path(path).resolve()
        return p == root or root in p.parents or p in root.parents
    except Exception:
        return False


def _process_launch(comfy_root: Path):
    for pid, cmd, image in _python_procs():
        if "main.py" not in cmd:
            continue
        cand = [image] if image else []
        cand += re.findall(r'[A-Za-z]:\\[^\s"\']+|/[^\s"\']+', cmd)
        if any(_under(comfy_root, c) for c in cand if c):
            flags = _extract_flags(cmd)
            if flags:
                return {"source": f"process:{pid}", "source_kind": "process",
                        "flags": flags, "raw": cmd[:300]}
    return None


# ---------- manager (T7) ----------

def _manager(root: Path) -> dict:
    mgr = {"present": False, "version": None, "dir": None, "config_path": None,
           "config_path_is_legacy": None, "security_level": None,
           "allow_pip_install": None, "allow_git_url_install": None,
           "network_mode": None, "bypass_ssl": None, "config": {}}
    for name in ("ComfyUI-Manager", "comfyui-manager", "comfyui_manager"):
        d = root / "custom_nodes" / name
        if d.exists():
            mgr["present"] = True
            mgr["dir"] = str(d.relative_to(root))
            mgr.update(_git_version(d))
            break
    for cfg, legacy in [
        (root / "user" / "__manager" / "config.ini", False),
        (root / "user" / "default" / "ComfyUI-Manager" / "config.ini", True),
    ]:
        if cfg.exists():
            mgr["present"] = True
            mgr["config_path"] = str(cfg.relative_to(root))
            mgr["config_path_is_legacy"] = legacy
            _parse_manager_config(cfg, mgr)
            break
    return mgr


def _git_version(d: Path) -> dict:
    out = {}
    tag = _run(["git", "describe", "--tags", "--abbrev=0"], cwd=d)
    if tag:
        out["version"] = tag.lstrip("v")
    else:
        for f in (d / "pyproject.toml", d / "__init__.py"):
            m = re.search(r'version\s*=\s*[\'"]([0-9][^\'"]*)', _read(f))
            if m:
                out["version"] = m.group(1)
                break
    return out


def _as_bool(v):
    if v is None:
        return None
    return str(v).strip().lower() == "true"


def _parse_manager_config(cfg: Path, mgr: dict):
    cp = configparser.ConfigParser()
    try:
        cp.read(cfg, encoding="utf-8")
    except Exception:
        return
    sec = "default" if cp.has_section("default") else (cp.sections()[0] if cp.sections() else None)
    if not sec:
        return
    mgr["config"] = dict(cp.items(sec))
    mgr["security_level"] = cp.get(sec, "security_level", fallback=None)
    mgr["network_mode"] = cp.get(sec, "network_mode", fallback=None)
    mgr["bypass_ssl"] = _as_bool(cp.get(sec, "bypass_ssl", fallback=None))
    # legacy keys (absent in Manager >= ~3.3x; kept for older installs)
    mgr["allow_pip_install"] = _as_bool(cp.get(sec, "allow_pip_install", fallback=None))
    mgr["allow_git_url_install"] = _as_bool(cp.get(sec, "allow_git_url_install", fallback=None))


# ---------- nodes (T5, T6) ----------

def _nodes(root: Path) -> list:
    nodes = []
    cn = root / "custom_nodes"
    if not cn.is_dir():
        return nodes
    for entry in sorted(cn.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name in SKIP_NODE_DIRS or entry.name.startswith("."):
            continue  # dot-dirs (.removed_packs_backup, .disabled) and non-pack dirs
        disabled = entry.name.endswith(".disabled")
        all_py = []
        for f in entry.rglob("*.py"):
            parts = {x.lower() for x in f.relative_to(entry).parts}
            if parts & SKIP_PACK_SUBDIRS or any(x.endswith(".disabled") for x in f.parts):
                continue
            all_py.append(f)
        all_py.sort(key=lambda f: (ENTRYPOINT_ORDER.get(f.name, 9), str(f)))
        py_files = all_py[:MAX_NODE_PY]
        js_files = [f for f in entry.rglob("*.js") if "__pycache__" not in f.parts][:20]
        reqs = entry / "requirements.txt"
        nodes.append({
            "name": entry.name,
            "path": str(entry.relative_to(root)),
            "abs_path": str(entry),
            "disabled": disabled,
            **_git_info(entry),
            "has_install_py": (entry / "install.py").exists(),
            "requirements_txt": str(reqs.relative_to(root)) if reqs.exists() else None,
            "py_files": [str(p) for p in py_files],
            "js_files": [str(p) for p in js_files],
            "files_total": len(all_py),
            "files_scanned": len(py_files),
        })
    return nodes


def _parse_requirements(text: str):
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        is_url = bool(re.match(r"(git\+|https?://)", line)) or " @ " in line
        pinned = "==" in line
        name = re.split(r"[<>=!~ \[]", line, 1)[0].strip()
        out.append({"raw": line, "name": name, "pinned": pinned, "url": is_url})
    return out


def _deps(root: Path, nodes: list) -> dict:
    declared = []
    root_req = root / "requirements.txt"
    if root_req.exists():
        for d in _parse_requirements(_read(root_req)):
            d["declared_in"] = "requirements.txt"
            declared.append(d)
    for n in nodes:
        if n.get("requirements_txt"):
            for d in _parse_requirements(_read(root / n["requirements_txt"])):
                d["declared_in"] = n["requirements_txt"]
                declared.append(d)
    return {"declared": declared}


def _models(root: Path) -> dict:
    from .data import PICKLE_EXTS, SAFE_MODEL_EXTS
    md = root / "models"
    files = []
    capped = False
    if md.is_dir():
        for f in md.rglob("*"):
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            if ext in PICKLE_EXTS or ext in SAFE_MODEL_EXTS:
                try:
                    size = f.stat().st_size
                except Exception:
                    size = None
                files.append({"path": str(f.relative_to(root)), "ext": ext, "size": size, "pickle": ext in PICKLE_EXTS})
                if len(files) >= MAX_MODELS:
                    capped = True
                    break
    return {"files": files, "capped": capped}


def _host(root: Path) -> dict:
    host = {"docker_user": None, "docker_user_source": None, "privileged": None,
            "exposed_ports": [], "mounts_docker_socket": None,
            "perms_check_available": os.name != "nt",
            "custom_nodes_writable": _world_or_group_writable(root / "custom_nodes"),
            "models_writable": _world_or_group_writable(root / "models")}
    for base in (root, root.parent):
        df = base / "Dockerfile"
        if df.exists():
            users = re.findall(r"(?im)^\s*USER\s+(\S+)", _read(df))
            host["docker_user"] = users[-1] if users else None
            host["docker_user_source"] = str(df.name)
            break
    for base in (root, root.parent):
        for comp in list(base.glob("docker-compose*.yml")) + list(base.glob("docker-compose*.yaml")):
            text = _read(comp)
            if re.search(r"(?im)privileged:\s*true", text):
                host["privileged"] = True
            if "/var/run/docker.sock" in text:
                host["mounts_docker_socket"] = True
            for port in re.findall(r"\"?(\d{2,5}):\d{2,5}\"?", text):
                if port in ("2375", "2376", "6379"):
                    host["exposed_ports"].append(port)
    return host


def _ioc(root: Path, nodes: list, deps: dict) -> dict:
    from .data import MALICIOUS_NODE_DIRS, BAD_PIP_PINS, IOC_HOST_PATHS
    ioc = {"host_artifacts": [], "malicious_nodes": [], "bad_pins": [], "poisoned_workflow": None}
    for p in IOC_HOST_PATHS:
        if Path(p).exists():
            ioc["host_artifacts"].append(p)
    for n in nodes:
        base = n["name"].lower()
        base = base[:-9] if base.endswith(".disabled") else base
        if base in MALICIOUS_NODE_DIRS:
            ioc["malicious_nodes"].append(n["path"])
    bad = {p.lower() for p in BAD_PIP_PINS}
    for d in deps.get("declared", []):
        if d["raw"].replace(" ", "").lower() in bad:
            ioc["bad_pins"].append(d["raw"])
    wf = root / "user" / "default" / "workflows" / "default.json"
    if wf.exists():
        text = _read(wf)
        if re.search(r"curl\s|wget\s|urllib|subprocess|os\.system|https?://[^\"']*\.(sh|py|txt)", text):
            ioc["poisoned_workflow"] = str(wf.relative_to(root))
    return ioc


def _firewall() -> dict:
    """Best-effort host firewall visibility (T12). Collects, never fails, and is
    used only to annotate exposure findings, never to downgrade them."""
    fw = {"available": False, "raw": None}
    try:
        if os.name == "nt":
            out = _run(["powershell", "-NoProfile", "-Command",
                        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
                        "Get-NetFirewallPortFilter | Select-Object -First 40 | Out-String"], timeout=10)
        else:
            out = _run(["ufw", "status"], timeout=5) or _run(["iptables", "-S"], timeout=5)
        if out:
            fw["available"] = True
            fw["raw"] = out[:2000]
    except Exception:
        pass
    return fw


def _network(url: str) -> dict:
    base = url.rstrip("/")
    host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
    out = {"url": base, "host": host, "loopback": host in LOOPBACK,
           "reachable": False, "https": base.lower().startswith("https"),
           "status": None, "auth_challenge": None, "cors": None, "server": None, "error": None}
    try:
        req = urllib.request.Request(base + "/system_stats", method="GET",
                                     headers={"User-Agent": "ComfyGuard/0.1 (read-only audit)"})
        with urllib.request.urlopen(req, timeout=6) as r:
            out["reachable"] = True
            out["status"] = r.status
            out["auth_challenge"] = bool(r.headers.get("WWW-Authenticate"))
            out["cors"] = r.headers.get("Access-Control-Allow-Origin")
            out["server"] = r.headers.get("Server")
    except urllib.error.HTTPError as e:
        out["reachable"] = True
        out["status"] = e.code
        out["auth_challenge"] = e.code in (401, 403) or bool(e.headers.get("WWW-Authenticate"))
        out["cors"] = e.headers.get("Access-Control-Allow-Origin") if e.headers else None
        out["server"] = e.headers.get("Server") if e.headers else None
    except Exception as e:
        out["error"] = str(e)
    return out
