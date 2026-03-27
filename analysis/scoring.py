"""Security Score — агрегирует находки всех стадий в единый скор 0–100."""
from __future__ import annotations

from dataclasses import dataclass, field

from analysis.severity import SeverityEngine
from models.report_v2 import FindingV2

# Веса стадий в итоговом скоре
STAGE_WEIGHTS: dict[str, float] = {"stage1": 0.40, "stage2": 0.30, "stage3": 0.30}

# Максимальная сумма «сырых» очков на каждую стадию (для нормализации).
# stage3 raised from 40 → 60: full MobSF+Quark+APKiD+APKLeaks on real malware
# easily exceeds 40, causing normalized=100 even at moderate finding counts.
STAGE_RAW_CAP: dict[str, float] = {"stage1": 50.0, "stage2": 30.0, "stage3": 60.0}

# Множители для уровней достоверности (совпадают с SeverityEngine)
CONF_MULT: dict[str, float] = {"C3": 1.0, "C2": 0.75, "C1": 0.5}

# Fallback severity → impact when category not in impact_table (BUG-REP-06)
_SEVERITY_TO_IMPACT: dict[str, int] = {"high": 4, "medium": 2, "low": 1, "info": 0}

# Cross-stage deduplication: categories representing the same underlying vulnerability.
# When a dedup group appears in multiple stages, secondary occurrences are scored at
# DEDUP_PENALTY_FACTOR to reflect confirmation without double-counting the full weight.
DEDUP_PENALTY_FACTOR: float = 0.2

# category → dedup_group name
DEDUP_GROUPS: dict[str, str] = {
    # cleartext transport (S1 static + S2 runtime + S3 MobSF)
    "sec_cleartext_http_endpoint":        "cleartext_transport",
    "sec_cleartext_http_protocol":        "cleartext_transport",
    "sec_cleartext_traffic_allowed":      "cleartext_transport",
    "sec_runtime_cleartext_transport":    "cleartext_transport",
    # secrets / hardcoded credentials (S1 rg/semgrep + S3 APKLeaks)
    "secret_private_key_pem":            "secrets",
    "secret_hardcoded_credentials":      "secrets",
    "secret_hardcoded_token_or_apikey":  "secrets",
    "apkleaks_secret":                   "secrets",
    "apkleaks_password":                 "secrets",
    "apkleaks_token":                    "secrets",
    "apkleaks_api_key":                  "secrets",
    # obfuscation (S1 anomaly + S3 APKiD)
    "anomaly_obfuscation_heavy":          "obfuscation",
    "supplychain_obfuscator_detected":    "obfuscation",
    # debuggable (S1 manifest — no Stage3 equivalent without title lookup)
    "vul_debuggable_true":               "debuggable",
    # exported components (S1 manifest + S3 MobSF/Quark)
    "vul_exported_component_no_permission": "exported_components",
    "vul_exported_provider_risky":          "exported_components",
}

# Stage priority for dedup: stage1 is canonical, stage2/3 are confirmatory
_STAGE_PRIORITY: dict[str, int] = {"stage1": 0, "stage2": 1, "stage3": 2}


@dataclass
class StageScore:
    stage: str
    raw_sum: float = 0.0
    normalized: float = 0.0   # 0–100
    findings_count: int = 0
    high_count: int = 0
    medium_count: int = 0


@dataclass
class SecurityScore:
    total: float = 0.0           # 0–100, взвешенная сумма по стадиям
    risk_label: str = "unknown"  # safe / low / medium / high / critical
    stages: dict[str, StageScore] = field(default_factory=dict)
    breakdown: dict[str, float] = field(default_factory=dict)


def _score_stage(
    stage: str,
    findings: list[FindingV2],
    penalized_categories: set[str] | None = None,
) -> StageScore:
    """Считает сырой и нормализованный скор для одной стадии.

    penalized_categories: findings in these categories are multiplied by
    DEDUP_PENALTY_FACTOR because the same vulnerability was already counted at
    full weight in a higher-priority stage.
    """
    result = StageScore(stage=stage, findings_count=len(findings))
    raw_sum = 0.0

    for f in findings:
        # BUG-ARCH-06: unknown category → 0 (not 1) to avoid score inflation
        base = SeverityEngine.impact_table.get(f.category, 0)
        # BUG-REP-06: fall back to pre-computed severity when category is unknown
        if base == 0:
            base = _SEVERITY_TO_IMPACT.get(f.severity or "info", 0)
        tag_boost = sum(SeverityEngine.tag_boosts.get(t, 0.0) for t in (f.tags or []))
        tag_boost = min(tag_boost, SeverityEngine.max_tag_boost)
        # Use C2 as a conservative fallback for unrecognised confidence values
        # instead of C1 (which halves the score without a clear reason).
        conf = f.confidence if f.confidence in CONF_MULT else "C2"
        item_score = (base + tag_boost) * CONF_MULT[conf]
        # Apply cross-stage dedup penalty for secondary occurrences.
        if penalized_categories and f.category in penalized_categories:
            item_score *= DEDUP_PENALTY_FACTOR
        raw_sum += item_score

        if f.severity == "high":
            result.high_count += 1
        elif f.severity == "medium":
            result.medium_count += 1

    result.raw_sum = round(raw_sum, 3)
    cap = STAGE_RAW_CAP.get(stage, 40.0)
    result.normalized = round(min(raw_sum / cap * 100.0, 100.0), 2)
    return result


def _risk_label(score: float) -> str:
    if score < 10:
        return "safe"
    if score < 30:
        return "low"
    if score < 55:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _build_dedup_penalties(
    findings_by_stage: dict[str, list[FindingV2]],
) -> dict[str, set[str]]:
    """Return {stage → set[category]} to penalise in _score_stage.

    A category is penalised in a stage if its dedup group is also present in a
    higher-priority stage (stage1 > stage2 > stage3).
    """
    # group → set of stages that contain this dedup group
    group_stages: dict[str, set[str]] = {}
    for stage, findings in findings_by_stage.items():
        for f in findings:
            group = DEDUP_GROUPS.get(f.category)
            if group:
                group_stages.setdefault(group, set()).add(stage)

    # Only groups appearing in 2+ stages need dedup
    multi_stage = {g for g, stages in group_stages.items() if len(stages) > 1}

    # For each stage, collect categories to penalise
    penalties: dict[str, set[str]] = {stage: set() for stage in findings_by_stage}
    for group in multi_stage:
        stages_with_group = group_stages[group]
        primary = min(stages_with_group, key=lambda s: _STAGE_PRIORITY.get(s, 99))
        for stage in stages_with_group:
            if stage == primary:
                continue
            for cat, g in DEDUP_GROUPS.items():
                if g == group:
                    penalties[stage].add(cat)

    return penalties


def compute_score(findings_by_stage: dict[str, list[FindingV2]]) -> SecurityScore:
    """Вычисляет SecurityScore из словаря {stage_name: [FindingV2, ...]}."""
    security = SecurityScore()
    total_weighted = 0.0
    breakdown: dict[str, float] = {}

    penalties = _build_dedup_penalties(findings_by_stage)

    for stage, findings in findings_by_stage.items():
        stage_score = _score_stage(stage, findings, penalized_categories=penalties.get(stage))
        security.stages[stage] = stage_score
        weight = STAGE_WEIGHTS.get(stage, 0.0)
        contribution = stage_score.normalized * weight
        breakdown[stage] = round(contribution, 2)
        total_weighted += contribution

    # Normalize by the sum of weights for stages that were actually run.
    # This prevents single-stage runs from being capped at STAGE_WEIGHTS[stage]*100.
    total_weight_used = sum(STAGE_WEIGHTS.get(stage, 0.0) for stage in findings_by_stage)
    if total_weight_used > 0:
        security.total = round(min(total_weighted / total_weight_used, 100.0), 2)
    else:
        # No findings data — return "unknown" instead of "safe" to avoid false reassurance
        security.total = 0.0
        security.risk_label = "unknown"
        security.breakdown = breakdown
        return security
    security.risk_label = _risk_label(security.total)
    security.breakdown = breakdown
    return security
