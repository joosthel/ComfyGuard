"""Bundled threat data, patterns, and the standing production warning.

This is the small, curated feed Phase 1 ships with. It is intentionally offline
so a scan works air-gapped. Keeping it current is how the tool stays useful; see
docs/RESEARCH.md for the evidence behind each entry.
"""

import re

# The warning shown in the CLI output and at the top of every report and plan.
PRODUCTION_WARNING = (
    "ComfyGuard is a starting point, not a turnkey fix.\n"
    "Applying changes to a deployed or production ComfyUI instance can break "
    "running pipelines and workflows.\n"
    "Review every proposed change, back up or snapshot first, test in a safe "
    "environment, and roll out carefully.\n"
    "ComfyGuard changes nothing on your instance. Every item in FIXES.md is a "
    "proposal for a human or agent to weigh, not an instruction to apply blindly."
)

# Known-malicious custom-node directory names (compared lowercased).
MALICIOUS_NODE_DIRS = {
    "comfyui_llmvision",
    "upscaler-4k",
    "lonemilk-upscalernew-4k",
    "comfyui-upscaler-4k",
    "comfyui_perf_monitor",
    "comfyui-shell-executor",
}

# Known-bad pip pins (from the documented supply-chain compromises).
BAD_PIP_PINS = {
    "ultralytics==8.3.41",
    "ultralytics==8.3.42",
    "ultralytics==8.3.45",
    "ultralytics==8.3.46",
    "litellm==1.82.7",
    "litellm==1.82.8",
}

# Node class names tied to intentional or known code execution (informational
# when merely present; escalated when reachable on a networked instance).
RISKY_NODE_CLASSES = {
    "LoadTrainingDataset",
    "ACE_ExpressionEval",
    "BuildColorRangeHSVAdvanced",
    "FL_CodeNode",
    "SrlEval",
    "EvaluateMultiple",
}

# Exfiltration-shaped destinations seen in real incidents.
SUSPICIOUS_NET_MARKERS = [
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org",
    "gofile.io",
    "pastebin.com",
    "transfer.sh",
    "0x0.st",
    "anonfiles",
    "file.io",
]

# Command-and-control / mining indicators from the 2026 botnet campaigns.
IOC_C2 = [
    "77.110.96.200",
    "209.99.186.235",
    "kryptex.network",
    "cdnorigin.net",
]

# Host-level compromise artifacts.
IOC_HOST_PATHS = ["/etc/ld.so.preload"]

PICKLE_EXTS = {".ckpt", ".pt", ".pth", ".bin", ".pkl", ".pwf"}
SAFE_MODEL_EXTS = {".safetensors", ".gguf"}

SECRET_KEY_HINT = re.compile(
    r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|_SECRET|_TOKEN|_PASSWORD|PASSWD|"
    r"API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)",
    re.I,
)
# Obvious credential value shapes, for a light secret scan of config files.
SECRET_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),      # GitHub token
    re.compile(r"sk-[A-Za-z0-9]{20,}"),             # OpenAI-style key
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),    # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

IP_LITERAL = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Default references attached to findings by check id.
REFERENCES = {
    "EXP-001": [{"type": "source", "url": "https://raw.githubusercontent.com/comfyanonymous/ComfyUI/master/comfy/cli_args.py"}],
    "EXP-002": [{"type": "policy", "url": "https://github.com/comfyanonymous/ComfyUI/blob/master/SECURITY.md"}],
    "EXP-003": [{"type": "source", "url": "https://raw.githubusercontent.com/comfyanonymous/ComfyUI/master/server.py"}],
    "EXP-004": [{"type": "guide", "url": "https://www.sygnal.com/kb/exposing-comfyui-as-an-external-api"}],
    "AUTH-001": [{"type": "policy", "url": "https://github.com/comfyanonymous/ComfyUI/blob/master/SECURITY.md"}],
    "API-008": [{"type": "source", "url": "https://raw.githubusercontent.com/comfyanonymous/ComfyUI/master/server.py"}],
    "PATCH-001": [{"type": "advisory", "id": "CVE-2026-56673", "url": "https://github.com/Comfy-Org/ComfyUI/security/advisories/GHSA-rvxv-29p8-pxgq"}],
    "PATCH-003": [{"type": "advisory", "id": "CVE-2025-67303", "url": "https://xlab.tencent.com/en/2026/01/06/xlab-26-001/"}],
    "PATCH-007": [{"type": "incident", "url": "https://blog.comfy.org/p/upscaler-4k-malicious-node-pack-post"}],
    "NODE-001": [{"type": "policy", "url": "https://docs.comfy.org/registry/standards"}],
    "NODE-002": [{"type": "policy", "url": "https://docs.comfy.org/registry/standards"}],
    "NODE-003": [{"type": "policy", "url": "https://docs.comfy.org/registry/standards"}],
    "NODE-004": [{"type": "policy", "url": "https://docs.comfy.org/registry/standards"}],
    "NODE-006": [{"type": "incident", "url": "https://www.vpnmentor.com/news/comfyui-malicious-custom-node/"}],
    "NODE-007": [{"type": "incident", "url": "https://www.vpnmentor.com/news/comfyui-malicious-custom-node/"}],
    "NODE-010": [{"type": "issue", "url": "https://github.com/Comfy-Org/ComfyUI/issues/12245"}],
    "NODE-011": [{"type": "policy", "url": "https://docs.comfy.org/registry/standards"}],
    "DEP-002": [{"type": "tool", "url": "https://github.com/pypa/pip-audit"}],
    "DEP-003": [{"type": "tool", "url": "https://github.com/pypa/pip-audit"}],
    "MODEL-001": [{"type": "tool", "url": "https://github.com/trailofbits/fickling"}],
    "HOST-001": [{"type": "guide", "url": "https://github.com/mmartial/ComfyUI-Nvidia-Docker"}],
    "HOST-006": [{"type": "doc", "url": "docs/CHECKS.md"}],
    "HOST-007": [{"type": "docs", "url": "https://docs.comfy.org/manager/configuration"}],
    "HOST-010": [{"type": "advisory", "id": "CVE-2025-67303", "url": "https://xlab.tencent.com/en/2026/01/06/xlab-26-001/"}],
    "HOST-014": [{"type": "incident", "url": "https://censys.com/blog/comfyui-servers-cryptomining-proxy-botnet/"}],
    "SEC-001": [{"type": "research", "url": "https://labs.snyk.io/resources/hacking-comfyui-through-custom-nodes/"}],
    "SEC-004": [{"type": "tool", "url": "https://github.com/gitleaks/gitleaks"}],
    "IOC-001": [{"type": "incident", "url": "https://censys.com/blog/comfyui-servers-cryptomining-proxy-botnet/"}],
    "IOC-004": [{"type": "incident", "url": "https://censys.com/blog/comfyui-servers-cryptomining-proxy-botnet/"}],
    "IOC-006": [{"type": "incident", "url": "https://thehackernews.com/2026/04/over-1000-exposed-comfyui-instances.html"}],
    "API-006": [{"type": "source", "url": "https://raw.githubusercontent.com/comfyanonymous/ComfyUI/master/server.py"}],
}


def refs(check_id):
    return REFERENCES.get(check_id, [{"type": "doc", "url": "docs/CHECKS.md"}])
