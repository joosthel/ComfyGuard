#!/usr/bin/env python3
"""Dependency-free test runner. Discovers test_*.py in this directory and runs
every test_* function. Also usable under pytest. Exit non-zero on any failure."""

import importlib
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import SkipTest  # noqa: E402


def main() -> int:
    passed = failed = skipped = 0
    fails = []
    for path in sorted(HERE.glob("test_*.py")):
        mod = importlib.import_module(path.stem)
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            fn = getattr(mod, name)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
                print(f"  PASS {path.stem}.{name}")
            except SkipTest as e:
                skipped += 1
                print(f"  SKIP {path.stem}.{name}: {e}")
            except Exception as e:  # noqa: BLE001
                failed += 1
                fails.append((f"{path.stem}.{name}", traceback.format_exc()))
                print(f"  FAIL {path.stem}.{name}: {e}")
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    for name, tb in fails:
        print(f"\n=== {name} ===\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
