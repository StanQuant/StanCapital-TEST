"""ATR 回應決策 · 0-100 分映射到五級動作，含受控抑制(D6)。"""

from __future__ import annotations

from src.security.atr.types import AtrAction, AtrDecision, SuppressionRule, ThreatLevel, ThreatScore

_LEVEL_ORDER = (
    ThreatLevel.SAFE,
    ThreatLevel.LOW,
    ThreatLevel.MEDIUM,
    ThreatLevel.HIGH,
    ThreatLevel.CRITICAL,
)


class AtrResponseHandler:
    """把 ThreatScore 轉成 AtrDecision。"""

    def __init__(self, suppressions: tuple[SuppressionRule, ...] = ()) -> None:
        self._suppressions = suppressions

    def decide(self, score: ThreatScore) -> AtrDecision:
        """依 Architecture §6.3 五級回應，並套用受控抑制。"""
        effective_level, applied = self._apply_suppression(score)
        if effective_level is ThreatLevel.SAFE:
            return AtrDecision(
                score=score,
                action=AtrAction.ALLOW,
                audit_required=True,
                encrypt_trace=False,
                suspend_agent=False,
                terminate_session=False,
                notify_security_officer=False,
                requires_human_approval=False,
                suppression_applied=applied,
            )
        if effective_level is ThreatLevel.LOW:
            return AtrDecision(
                score=score,
                action=AtrAction.LOG,
                audit_required=True,
                encrypt_trace=False,
                suspend_agent=False,
                terminate_session=False,
                notify_security_officer=False,
                requires_human_approval=False,
                suppression_applied=applied,
            )
        if effective_level is ThreatLevel.MEDIUM:
            return AtrDecision(
                score=score,
                action=AtrAction.ENCRYPT,
                audit_required=True,
                encrypt_trace=True,
                suspend_agent=False,
                terminate_session=False,
                notify_security_officer=False,
                requires_human_approval=False,
                suppression_applied=applied,
            )
        if effective_level is ThreatLevel.HIGH:
            return AtrDecision(
                score=score,
                action=AtrAction.SUSPEND,
                audit_required=True,
                encrypt_trace=True,
                suspend_agent=True,
                terminate_session=False,
                notify_security_officer=True,
                requires_human_approval=False,
                suppression_applied=applied,
            )
        return AtrDecision(
            score=score,
            action=AtrAction.TERMINATE,
            audit_required=True,
            encrypt_trace=True,
            suspend_agent=True,
            terminate_session=True,
            notify_security_officer=True,
            requires_human_approval=True,
            suppression_applied=applied,
        )

    def _apply_suppression(
        self, score: ThreatScore
    ) -> tuple[ThreatLevel, tuple[SuppressionRule, ...]]:
        """受控抑制最多降低一級，且 high / critical 不可降成 safe。"""
        matched = tuple(
            rule
            for rule in self._suppressions
            if rule.tenant_id == score.tenant_id
            and any(triggered.code is rule.threat_code for triggered in score.triggered_rules)
        )
        if not matched:
            return score.level, ()
        level_index = _LEVEL_ORDER.index(score.level)
        reduction = min(sum(rule.max_level_reduction for rule in matched), 1)
        reduced_index = max(level_index - reduction, 0)
        if score.level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            reduced_index = max(reduced_index, _LEVEL_ORDER.index(ThreatLevel.MEDIUM))
        return _LEVEL_ORDER[reduced_index], matched
