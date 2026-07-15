"""
Contextual Risk Score engine — shared across all Kaaval finding types
(CVE, RBAC, and whatever comes next).

Score = base severity x environment weight x data classification weight x
        compliance scope weight x exposure weight — see project_usp.md.
The point is not the number, it's that every finding says *why* it ranks
where it does, instead of a flat severity sort every competitor already does.
"""

from typing import Optional

_SEVERITY_BASE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5, "UNKNOWN": 1.0}
_ENV_WEIGHT = {"production": 1.5, "staging": 1.2, "dev": 0.5}
_DATA_CLASS_WEIGHT = {"pii": 1.5, "financial": 1.5, "phi": 1.5, "internal": 1.0, "public": 0.8}
_EXPOSURE_WEIGHT = {"internet-facing": 1.4, "internal": 1.0}

MAX_CONTEXTUAL_SCORE = (
    max(_SEVERITY_BASE.values())
    * max(_ENV_WEIGHT.values())
    * max(_DATA_CLASS_WEIGHT.values())
    * 1.3  # max compliance_weight
    * max(_EXPOSURE_WEIGHT.values())
)

# Allowed risk-context values — shared by the HTTP API and the CLI so both
# validate against the same enums the weights above understand.
VALID_ENVIRONMENTS = set(_ENV_WEIGHT)
VALID_DATA_CLASSIFICATIONS = set(_DATA_CLASS_WEIGHT)
VALID_EXPOSURES = set(_EXPOSURE_WEIGHT)
SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def compute_contextual_score(
    raw_score: Optional[float], severity: str, context: dict
) -> tuple[float, dict]:
    """
    Compute an explainable Contextual Risk Score for one finding, from any
    finding type (a CVE's CVSS score, an RBAC rule's baseline severity, etc).

    Returns (score, factors) where `factors` names each multiplier applied,
    so the score is never a black box — it's the whole point of the feature.
    """
    base = raw_score if raw_score is not None else _SEVERITY_BASE.get(severity, 1.0)

    environment = context.get("environment", "production")
    data_classification = context.get("data_classification", "internal")
    compliance_scope = context.get("compliance_scope") or []
    exposure = context.get("exposure", "internal")

    env_weight = _ENV_WEIGHT.get(environment, 1.0)
    data_weight = _DATA_CLASS_WEIGHT.get(data_classification, 1.0)
    compliance_weight = 1.3 if compliance_scope else 1.0
    exposure_weight = _EXPOSURE_WEIGHT.get(exposure, 1.0)

    score = base * env_weight * data_weight * compliance_weight * exposure_weight

    factors = {
        "base_severity": {"value": severity, "raw_score": raw_score, "weight": round(base, 2)},
        "environment": {"value": environment, "weight": env_weight},
        "data_classification": {"value": data_classification, "weight": data_weight},
        "compliance_scope": {"value": compliance_scope, "weight": compliance_weight},
        "exposure": {"value": exposure, "weight": exposure_weight},
    }
    return round(score, 2), factors
