"""Finding model, severity ordering, and the deployment grade."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
URGENCIES = {"blocker", "urgent", "standard", "hardening"}


@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    severity: str
    description: str
    impact: str = ""
    confidence: str = "medium"
    urgency: str = "standard"
    decision_owner: str = "agent"  # "agent" or "human"
    location: dict = field(default_factory=dict)
    evidence: str = ""
    remediation: dict = field(default_factory=dict)
    references: list = field(default_factory=list)
    fingerprint: str = ""

    def finalize(self) -> "Finding":
        if not self.fingerprint:
            loc = self.location or {}
            basis = "|".join(
                str(x)
                for x in (
                    self.check_id,
                    loc.get("path", ""),
                    loc.get("line", ""),
                    loc.get("symbol", ""),
                    self.evidence[:60],
                )
            )
            digest = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:10]
            self.fingerprint = f"{self.check_id.lower()}-{digest}"
        return self

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.urgency != "blocker", f.check_id),
    )


def grade(findings) -> str:
    """A-to-F grade driven by the worst confirmed finding (see docs/REPORTING.md)."""
    crit_high_conf = any(f.severity == "critical" and f.confidence == "high" for f in findings)
    crit_any = any(f.severity == "critical" for f in findings)
    highs = sum(1 for f in findings if f.severity == "high")
    if crit_high_conf:
        return "F"
    if crit_any or highs >= 2:
        return "D"
    if highs >= 1:
        return "C"
    if any(f.severity == "medium" for f in findings):
        return "B"
    return "A"


def grade_reason(findings, g) -> str:
    if g == "A":
        return "No known-bad patterns, versions, or configurations were found. This is not proof the instance is safe."
    drivers = [f for f in findings if f.severity in ("critical", "high")]
    drivers = sort_findings(drivers)[:3]
    names = "; ".join(f"{f.check_id} ({f.title})" for f in drivers)
    return f"Set by: {names}."
