"""Launch detection and exposure across install layouts. These are the instances
we cannot physically test, built synthetically."""

import tempfile
from pathlib import Path

import harness as h


def test_windows_portable_subdir_detects_exposure():
    with tempfile.TemporaryDirectory() as t:
        comfy = h.windows_portable(t)
        rep, _ = h.audit(comfy)  # audit the ComfyUI subdir; launcher is in the parent
        assert "EXP-001" in h.ids(rep), "launcher in the portable parent must be found"
        assert rep["summary"]["pre_exposure_gate_passed"] is False


def test_windows_portable_root_finds_nodes():
    with tempfile.TemporaryDirectory() as t:
        comfy = h.windows_portable(t)
        rep, _ = h.audit(comfy.parent)  # audit the portable root
        assert rep["scan"]["target"]["custom_node_packs"] >= 1, "root audit must descend into ComfyUI/"
        assert "EXP-001" in h.ids(rep)


def test_flat_portable():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.flat_portable(t))
        assert "EXP-001" in h.ids(rep)


def test_linux_systemd_unit():
    with tempfile.TemporaryDirectory() as t:
        rep, facts = h.audit(h.linux_systemd(t))
        assert "EXP-001" in h.ids(rep), "systemd unit under deploy/ must be parsed"
        assert facts["launch"]["source"] and facts["launch"]["source"].endswith(".service")


def test_compose_published_port_is_exposure():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.compose_exposed(t))
        ids = h.ids(rep)
        assert "EXP-001" in ids, "a compose-published port on 0.0.0.0 is exposure"
        assert "HOST-002" in ids, "privileged container"
        assert "HOST-001" in ids, "root container"
        assert rep["summary"]["pre_exposure_gate_passed"] is False


def test_clean_loopback_grades_a():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.clean_loopback(t))
        assert rep["summary"]["grade"] == "A", rep["summary"]["grade_reason"]
        assert "EXP-001" not in h.ids(rep)
        assert "EXP-000" not in h.ids(rep)
        assert rep["summary"]["pre_exposure_gate_passed"] is True


def test_undetermined_fails_safe():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.undetermined(t))
        assert "EXP-000" in h.ids(rep), "undetermined bind config must fail the gate, not pass silently"
        assert rep["summary"]["pre_exposure_gate_passed"] is False


def test_symlink_loop_terminates():
    with tempfile.TemporaryDirectory() as t:
        root = h.symlink_loop(t)
        if root is None:
            h.skip("symlinks not permitted on this platform")
        rep, _ = h.audit(root)  # must not hang on the directory loop
        assert rep["summary"]["grade"] in ("A", "B", "C", "D", "F")
