"""Read-only collectors. They only read from the install and, optionally, make
safe GET probes against an authorized URL. They never modify anything."""

from __future__ import annotations

import configparser
import json
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

MAX_NODE_PY = 60         # cap python files scanned per node
MAX_FILE_BYTES = 1_500_000
MAX_MODELS = 2000


def looks_like_comfyui(root: Path) -> bool:
    return any((root / p).exists() for p in ("main.py", "comfy", "custom_nodes", "nodes.py", "comfyui_version.py"))


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
    try:
        mode = p.stat().st_mode
        return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
    except Exception:
        return None


def collect(root, url=None, authorized=False) -> dict:
    root = Path(root).expanduser().resolve()
    facts = {
        "root": str(root),
        "is_comfyui": looks_like_comfyui(root),
        "scanner": {"uid": os.geteuid() if hasattr(os, "geteuid") else None, "platform": os.name},
    }
    facts["core"] = _core(root)
    facts["launch"] = _launch(root)
    facts["manager"] = _manager(root)
    facts["nodes"] = _nodes(root)
    facts["deps"] = _deps(root, facts["nodes"])
    facts["models"] = _models(root)
    facts["host"] = _host(root)
    facts["ioc"] = _ioc(root, facts["nodes"], facts["deps"])
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


def _iter_launch_files(root: Path):
    patterns = ["*.sh", "*.bat", "*.service", "*.conf", "Dockerfile", "docker-compose*.yml", "docker-compose*.yaml"]
    seen = set()
    for pat in patterns:
        for p in list(root.glob(pat)) + list(root.glob("**/deploy/" + pat)):
            if p.is_file() and p not in seen:
                seen.add(p)
                yield p


def _launch(root: Path) -> dict:
    result = {"source": None, "flags": {}, "raw": None}
    for p in _iter_launch_files(root):
        text = _read(p)
        for line in text.splitlines():
            if "main.py" not in line and "ComfyUI" not in line and "comfyui" not in line:
                continue
            if "--" not in line:
                continue
            flags = {}
            for name, rx in LAUNCH_FLAG_RE.items():
                m = rx.search(line)
                if m:
                    flags[name] = m.group(1) if m.groups() and m.group(1) is not None else True
            if flags:
                result = {"source": str(p.relative_to(root)) if p.is_relative_to(root) else str(p),
                          "flags": flags, "raw": line.strip()[:300]}
                return result
    return result


def _manager(root: Path) -> dict:
    mgr = {"present": False, "version": None, "dir": None, "config_path": None,
           "config_path_is_legacy": None, "security_level": None,
           "allow_pip_install": None, "allow_git_url_install": None}
    for name in ("ComfyUI-Manager", "comfyui-manager", "comfyui_manager"):
        d = root / "custom_nodes" / name
        if d.exists():
            mgr["present"] = True
            mgr["dir"] = str(d.relative_to(root))
            mgr.update(_git_version(d))
            break
    # config, new protected path first, then legacy
    candidates = [
        (root / "user" / "__manager" / "config.ini", False),
        (root / "user" / "default" / "ComfyUI-Manager" / "config.ini", True),
    ]
    for cfg, legacy in candidates:
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
        # try a pyproject / __init__ version
        for f in (d / "pyproject.toml", d / "__init__.py"):
            m = re.search(r'version\s*=\s*[\'"]([0-9][^\'"]*)', _read(f))
            if m:
                out["version"] = m.group(1)
                break
    return out


def _parse_manager_config(cfg: Path, mgr: dict):
    cp = configparser.ConfigParser()
    try:
        cp.read(cfg, encoding="utf-8")
    except Exception:
        return
    sec = "default" if cp.has_section("default") else (cp.sections()[0] if cp.sections() else None)
    if not sec:
        return
    g = lambda k: cp.get(sec, k, fallback=None)
    mgr["security_level"] = g("security_level")
    for k in ("allow_pip_install", "allow_git_url_install"):
        v = g(k)
        mgr[k] = (str(v).strip().lower() == "true") if v is not None else None


def _nodes(root: Path) -> list:
    nodes = []
    cn = root / "custom_nodes"
    if not cn.is_dir():
        return nodes
    for entry in sorted(cn.iterdir()):
        if not entry.is_dir() or entry.name in ("__pycache__",):
            continue
        disabled = entry.name.endswith(".disabled")
        py_files = []
        for f in entry.rglob("*.py"):
            if "__pycache__" in f.parts:
                continue
            py_files.append(f)
            if len(py_files) >= MAX_NODE_PY:
                break
        js_files = [f for f in entry.rglob("*.js") if "__pycache__" not in f.parts][:20]
        reqs = entry / "requirements.txt"
        nodes.append({
            "name": entry.name,
            "path": str(entry.relative_to(root)),
            "abs_path": str(entry),
            "disabled": disabled,
            **_git_info(entry),
            "has_install_py": (entry / "install.py").exists(),
            "requirements_txt": str((reqs).relative_to(root)) if reqs.exists() else None,
            "py_files": [str(p) for p in py_files],
            "js_files": [str(p) for p in js_files],
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
                files.append({
                    "path": str(f.relative_to(root)),
                    "ext": ext,
                    "size": size,
                    "pickle": ext in PICKLE_EXTS,
                })
                if len(files) >= MAX_MODELS:
                    capped = True
                    break
    return {"files": files, "capped": capped}


def _host(root: Path) -> dict:
    host = {"docker_user": None, "docker_user_source": None, "privileged": None,
            "exposed_ports": [], "mounts_docker_socket": None,
            "custom_nodes_writable": _world_or_group_writable(root / "custom_nodes"),
            "models_writable": _world_or_group_writable(root / "models")}
    df = root / "Dockerfile"
    if df.exists():
        users = re.findall(r"(?im)^\s*USER\s+(\S+)", _read(df))
        host["docker_user"] = users[-1] if users else None
        host["docker_user_source"] = "Dockerfile"
    for comp in list(root.glob("docker-compose*.yml")) + list(root.glob("docker-compose*.yaml")):
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
        if n["name"].lower().rstrip(".disabled") in MALICIOUS_NODE_DIRS or n["name"].lower() in MALICIOUS_NODE_DIRS:
            ioc["malicious_nodes"].append(n["path"])
    for d in deps.get("declared", []):
        if d["raw"].replace(" ", "").lower() in {p.lower() for p in BAD_PIP_PINS}:
            ioc["bad_pins"].append(d["raw"])
    wf = root / "user" / "default" / "workflows" / "default.json"
    if wf.exists():
        text = _read(wf)
        if re.search(r"curl\s|wget\s|urllib|subprocess|os\.system|http://|https://[^\"']*\.(sh|py|txt)", text):
            ioc["poisoned_workflow"] = str(wf.relative_to(root))
    return ioc


def _network(url: str) -> dict:
    base = url.rstrip("/")
    out = {"url": base, "reachable": False, "https": base.lower().startswith("https"),
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
