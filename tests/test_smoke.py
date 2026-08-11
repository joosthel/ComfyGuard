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


def _build(root: Path):
    def w(rel, text):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    w("main.py", "# entry\n")
    w("comfyui_version.py", '__version__ = "0.3.62"\n')
    w("run.sh", "python main.py --listen 0.0.0.0 --enable-cors-header\n")
    w("models/checkpoints/base.safetensors", "safe")
    w("models/checkpoints/x.ckpt", "pickle")
    w("custom_nodes/ComfyUI-Manager/pyproject.toml", 'version = "3.29.0"\n')
    w("user/default/ComfyUI-Manager/config.ini",
      "[default]\nsecurity_level = weak\nallow_pip_install = True\n")
    w("custom_nodes/comfyui_perf_monitor/__init__.py", "NODE_CLASS_MAPPINGS = {}\n")
    w("custom_nodes/handy/__init__.py",
      "import subprocess\nsubprocess.run('x', shell=True)\n")
    w("custom_nodes/handy/nodes.py",
      "import base64, subprocess, requests, torch\n"
      "def f(e, p):\n"
      "    eval(e)\n"
      "    subprocess.run(['pip','install','z'])\n"
      "    requests.post('https://discord.com/api/webhooks/1/2')\n"
      "    torch.load(p)\n"
      "    exec(base64.b64decode('eA==').decode())\n")
    w("custom_nodes/handy/requirements.txt", "somepkg\n")


def run():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "comfyui"
        _build(root)
        facts = collectors.collect(root)
        findings = run_checks(facts, root)
        rep = report_mod.build_report(facts, findings, {"started_at": "t", "duration_seconds": 0})
        ids = {f["check_id"] for f in rep["findings"]}
        expected = {"EXP-001", "EXP-003", "AUTH-001", "PATCH-007", "HOST-007",
                    "NODE-001", "NODE-003", "NODE-006", "NODE-010", "MODEL-001"}
        missing = expected - ids
        assert not missing, f"missing expected findings: {missing}"
        assert rep["summary"]["grade"] == "F", rep["summary"]["grade"]
        assert rep["summary"]["pre_exposure_gate_passed"] is False
        assert "production_warning" in rep["notices"]
        # read-only: no report files written into the scanned tree
        assert not (root / "report.json").exists()
        return ids


def test_smoke():
    run()


if __name__ == "__main__":
    found = run()
    print(f"OK: smoke test passed, {len(found)} check families fired")
