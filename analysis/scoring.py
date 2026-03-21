"""Security Score — агрегирует находки всех стадий в единый скор 0–100."""
from __future__ import annotations

from dataclasses import dataclass, field

from analysis.severity import SeverityEngine
from models.report_v2 import FindingV2

# Веса стадий в итоговом скоре
STAGE_WEIGHTS: dict[str, float] = {"stage1": 0.40, "stage2": 0.30, "stage3": 0.30}

# Максимальная сумма «сырых» очков на каждую стадию (для нормализации)
STAGE_RAW_CAP: dict[str, float] = {"stage1": 50.0, "stage2": 30.0, "stage3": 40.0}

# Множители для уровней достоверности (совпадают с SeverityEngine)
CONF_MULT: dict[str, float] = {"C3": 1.0, "C2": 0.75, "C1": 0.5}


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


def _score_stage(stage: str, findings: list[FindingV2]) -> StageScore:
    """Считает сырой и нормализованный скор для одной стадии."""
    result = StageScore(stage=stage, findings_count=len(findings))
    raw_sum = 0.0

    for f in findings:
        base = SeverityEngine.impact_table.get(f.category, 1)
        tag_boost = sum(SeverityEngine.tag_boosts.get(t, 0.0) for t in (f.tags or []))
        tag_boost = min(tag_boost, SeverityEngine.max_tag_boost)
        conf = f.confidence if f.confidence in CONF_MULT else "C1"
        item_score = (base + tag_boost) * CONF_MULT[conf]
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


def compute_score(findings_by_stage: dict[str, list[FindingV2]]) -> SecurityScore:
    """Вычисляет SecurityScore из словаря {stage_name: [FindingV2, ...]}."""
    security = SecurityScore()
    total_weighted = 0.0
    breakdown: dict[str, float] = {}

    for stage, findings in findings_by_stage.items():
        stage_score = _score_stage(stage, findings)
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
        security.total = 0.0
    security.risk_label = _risk_label(security.total)
    security.breakdown = breakdown
    return security
