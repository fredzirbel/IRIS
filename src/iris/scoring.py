"""Central scoring engine for IRIS.

Classifies URLs into a 3-tier system (Safe / Uncertain / Malicious) with a
confidence percentage that reflects how strongly the evidence agrees on the
classification.  Threat feed matches are treated as weighted signals — not
binary overrides — so a single low-confidence hit is distinguished from
unanimous feed agreement.
"""

from __future__ import annotations

from typing import Any

from iris.models import AnalyzerResult, AnalyzerStatus, FeedResult, RiskCategory

# Default per-feed weights used when config does not specify them.
_DEFAULT_FEED_WEIGHTS: dict[str, float] = {
    "VirusTotal": 40.0,
    "Google Safe Browsing": 35.0,
    "AbuseIPDB": 25.0,
}


def calculate_score(
    results: list[AnalyzerResult],
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> tuple[float, RiskCategory, float]:
    """Aggregate analyzer results into a classification and confidence.

    The pipeline is:
      1. Weighted average of completed analyzer scores (0-100).
      2. Graduated feed signal (0-100) based on which feeds matched.
      3. Composite score blending analyzers and feeds.
      4. 3-tier classification via configurable thresholds.
      5. Confidence percentage reflecting signal agreement.

    Args:
        results: List of AnalyzerResult from all analyzers.
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        Tuple of (composite_score, risk_category, confidence_pct).
    """
    completed = [r for r in results if r.status == AnalyzerStatus.COMPLETED]

    if not completed:
        has_match = any(fr.matched for fr in feed_results)
        if has_match:
            return 100.0, RiskCategory.MALICIOUS, 60.0
        return 0.0, RiskCategory.SAFE, 50.0

    # ------------------------------------------------------------------
    # Step 1: Raw weighted analyzer score
    # ------------------------------------------------------------------
    total_weight = sum(r.max_weight for r in completed)
    raw_score = 0.0
    for result in completed:
        normalized_weight = result.max_weight / total_weight
        raw_score += result.score * normalized_weight

    # ------------------------------------------------------------------
    # Step 2: Graduated feed signal
    # ------------------------------------------------------------------
    feed_signal = _compute_feed_signal(feed_results, config)

    # ------------------------------------------------------------------
    # Step 3: Composite score (blend analyzers + feeds)
    # ------------------------------------------------------------------
    scoring_cfg = config.get("scoring", {})
    blend = scoring_cfg.get("blend", {})
    analyzer_blend = blend.get("analyzer_weight", 0.45)
    feed_blend = blend.get("feed_weight", 0.55)

    # If no feeds are configured at all, give all weight to analyzers.
    configured_feed_weights = scoring_cfg.get("feed_weights", _DEFAULT_FEED_WEIGHTS)
    has_any_feed_configured = len(feed_results) > 0
    if not has_any_feed_configured:
        analyzer_blend = 1.0
        feed_blend = 0.0

    composite = (raw_score * analyzer_blend) + (feed_signal * feed_blend)
    composite = min(100.0, max(0.0, composite))

    # ------------------------------------------------------------------
    # Step 4: 3-tier classification
    # ------------------------------------------------------------------
    thresholds = scoring_cfg.get("thresholds", {})
    safe_max = thresholds.get("safe", 25)
    malicious_min = thresholds.get("malicious", 60)

    if composite <= safe_max:
        category = RiskCategory.SAFE
    elif composite >= malicious_min:
        category = RiskCategory.MALICIOUS
    else:
        category = RiskCategory.UNCERTAIN

    # ------------------------------------------------------------------
    # Step 5: Confidence percentage
    # ------------------------------------------------------------------
    confidence = _calculate_confidence(
        completed, composite, feed_signal, category, thresholds,
    )

    return round(composite, 1), category, confidence


def _compute_feed_signal(
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> float:
    """Compute a 0-100 feed signal based on which feeds matched.

    Each feed has a configurable weight reflecting its reliability.
    The signal is the proportion of matched feed weight to total feed weight.

    Args:
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        Feed signal strength on a 0-100 scale.
    """
    configured_weights = (
        config.get("scoring", {}).get("feed_weights", _DEFAULT_FEED_WEIGHTS)
    )

    total_feed_weight = 0.0
    matched_feed_weight = 0.0

    for fr in feed_results:
        w = configured_weights.get(fr.feed_name, 30.0)
        total_feed_weight += w
        if fr.matched:
            matched_feed_weight += w

    if total_feed_weight <= 0:
        return 0.0

    return (matched_feed_weight / total_feed_weight) * 100.0


def _calculate_confidence(
    completed: list[AnalyzerResult],
    composite_score: float,
    feed_signal: float,
    category: RiskCategory,
    thresholds: dict[str, Any],
) -> float:
    """Calculate confidence as a percentage (50-99).

    Confidence is high when:
      - The composite score is far from the classification boundaries.
      - Individual analyzer scores agree with each other (low variance).
      - Feed results reinforce the analyzer findings.

    Confidence is low when:
      - The composite score is near a threshold boundary.
      - Analyzers disagree (some high, some low).
      - Feed results contradict analyzer findings.

    Args:
        completed: List of completed AnalyzerResults.
        composite_score: The blended composite score.
        feed_signal: Feed signal strength (0-100).
        category: The assigned RiskCategory.
        thresholds: Threshold config dict with 'safe' and 'malicious' keys.

    Returns:
        Confidence percentage rounded to 1 decimal (50.0-99.0).
    """
    safe_max = thresholds.get("safe", 25)
    malicious_min = thresholds.get("malicious", 60)

    # --- Component 1: Distance from nearest boundary (0-1 scale) ---
    if category == RiskCategory.SAFE:
        distance = (safe_max - composite_score) / max(safe_max, 1)
    elif category == RiskCategory.MALICIOUS:
        distance = (composite_score - malicious_min) / max(100 - malicious_min, 1)
    else:  # UNCERTAIN
        mid = (safe_max + malicious_min) / 2.0
        span = (malicious_min - safe_max) / 2.0
        distance = abs(composite_score - mid) / max(span, 1)

    boundary_confidence = min(1.0, max(0.0, distance))

    # --- Component 2: Analyzer agreement (1 - normalized std deviation) ---
    if len(completed) >= 2:
        scores = [r.score for r in completed]
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev = variance ** 0.5
        # Normalize: std_dev of 50 (max possible disagreement) → 0 agreement
        agreement = 1.0 - min(1.0, std_dev / 50.0)
    else:
        agreement = 0.5  # single analyzer → moderate agreement

    # --- Component 3: Feed reinforcement ---
    if category == RiskCategory.MALICIOUS:
        feed_reinforcement = feed_signal / 100.0
    elif category == RiskCategory.SAFE:
        feed_reinforcement = 1.0 - (feed_signal / 100.0)
    else:
        feed_reinforcement = 0.5  # feeds are ambiguous in uncertain zone

    # --- Weighted combination ---
    raw_confidence = (
        boundary_confidence * 0.45
        + agreement * 0.30
        + feed_reinforcement * 0.25
    )

    # Scale to 50-99 range — a completed scan should never show <50%.
    scaled = 50.0 + raw_confidence * 49.0

    return round(min(99.0, max(50.0, scaled)), 1)
