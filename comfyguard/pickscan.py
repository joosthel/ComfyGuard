"""Static pickle-opcode inspection for model files. It disassembles the pickle
stream with the standard library `pickletools` and flags references to dangerous
callables. It NEVER unpickles or executes anything.

Handles both raw pickles (.pkl, old .ckpt) and the zip container PyTorch uses
(scanning the embedded data.pkl without extracting tensors)."""

from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path

# Modules whose presence in a model pickle is a code-execution red flag.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "builtins", "__builtin__",
    "socket", "shutil", "pty", "commands", "runpy", "webbrowser", "ctypes",
    "importlib", "pip", "requests", "urllib", "urllib.request", "code",
}
# Callable names that are dangerous regardless of the module claimed.
DANGEROUS_NAMES = {
    "system", "popen", "spawn", "spawnl", "spawnv", "fork", "exec", "execv",
    "execve", "eval", "compile", "__import__", "check_output", "check_call",
    "call", "run", "Popen", "getattr", "loads", "load", "connect", "urlopen",
}
MAX_RAW_PICKLE_BYTES = 64 * 1024 * 1024  # scan raw pickles up to 64MB; zip data.pkl always
STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
              "SHORT_BINSTRING", "BINSTRING", "UNICODE", "STRING"}


def _flag(module: str, name: str) -> bool:
    module = (module or "").strip()
    name = (name or "").strip()
    top = module.split(".")[0]
    if module in DANGEROUS_MODULES or top in DANGEROUS_MODULES:
        return True
    if name in DANGEROUS_NAMES and top not in ("torch", "numpy", "collections", "_codecs"):
        return True
    return False


def _scan_stream(f) -> list:
    hits = []
    recent = []
    try:
        for op, arg, _pos in pickletools.genops(f):
            nm = op.name
            if nm in STRING_OPS:
                recent.append(str(arg))
                recent = recent[-2:]
            elif nm == "GLOBAL":
                # arg is "module name"
                parts = str(arg).split(" ", 1) if arg else [""]
                module = parts[0]
                name = parts[1] if len(parts) > 1 else ""
                if _flag(module, name):
                    hits.append((module, name))
            elif nm == "STACK_GLOBAL":
                if len(recent) >= 2 and _flag(recent[-2], recent[-1]):
                    hits.append((recent[-2], recent[-1]))
            if len(hits) >= 8:
                break
    except Exception:
        pass  # truncated/odd pickle; report what we found
    return hits


def scan_pickle_file(path) -> list:
    """Return a list of (module, name) dangerous globals found, or []."""
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            magic = fh.read(4)
    except Exception:
        return []
    hits = []
    if magic[:2] == b"PK":  # zip container (PyTorch .pt/.ckpt)
        try:
            with zipfile.ZipFile(p) as z:
                for name in z.namelist():
                    if name.endswith(".pkl") or name.endswith("data.pkl"):
                        with z.open(name) as f:
                            hits += _scan_stream(io.BufferedReader(f))
                        if len(hits) >= 8:
                            break
        except Exception:
            pass
    else:
        try:
            if p.stat().st_size <= MAX_RAW_PICKLE_BYTES:
                with open(p, "rb") as f:
                    hits += _scan_stream(f)
        except Exception:
            pass
    # de-duplicate, preserve order
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out
