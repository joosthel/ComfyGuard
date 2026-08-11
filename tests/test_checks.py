"""Per-check behavior, including the false-positive regressions the test run found."""

import tempfile

import harness as h


def test_eval_method_not_flagged():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        # exactly one NODE-001 (the builtin eval), not the .eval()/.exec() methods
        assert h.count(rep, "NODE-001") == 1, "T2: method .eval()/.exec() must not be flagged"


def test_node_code_patterns():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        ids = h.ids(rep)
        for cid in ("NODE-002", "NODE-003", "NODE-004", "NODE-006", "NODE-010"):
            assert cid in ids, f"expected {cid}"


def test_disabled_backup_skipped():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        assert not any(".removed_packs_backup" in f["location"].get("path", "") for f in rep["findings"]), "T5"


def test_unparseable_disclosed():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        assert "SCAN-002" in h.ids(rep), "an unparseable node file must be disclosed"


def test_deps_unpinned_and_url():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        ids = h.ids(rep)
        assert "DEP-002" in ids and "DEP-003" in ids


def test_models_pickle_info():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        assert "MODEL-001" in h.ids(rep)


def test_manager_normal_networked_flags_host007():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.manager_normal_networked(t))
        h007 = [f for f in rep["findings"] if f["check_id"] == "HOST-007"]
        assert h007, "T7: security_level=normal on a networked instance must be flagged"
        assert "normal" in h007[0]["evidence"]


def test_ioc_malicious_node_and_workflow():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.ioc_case(t))
        ids = h.ids(rep)
        assert "PATCH-007" in ids, "known-malicious node dir"
        assert "IOC-004" in ids, "poisoned auto-run workflow"
        assert rep["summary"]["grade"] == "F"


def test_read_only_writes_nothing_into_tree():
    with tempfile.TemporaryDirectory() as t:
        root = h.node_corpus(t)
        before = {p for p in root.rglob("*")}
        h.audit(root)
        after = {p for p in root.rglob("*")}
        assert before == after, "audit must not write into the scanned tree"


def test_bom_and_launch_in_report():
    with tempfile.TemporaryDirectory() as t:
        rep, _ = h.audit(h.node_corpus(t))
        assert "bom" in rep and "nodes" in rep["bom"]
        assert "launch" in rep["scan"]


def test_exp004_loopback_probe_skipped():
    # Requires a live loopback HTTP server to probe; not available in unit tests.
    h.skip("network probe requires a running instance; covered by code review of _network_checks")
