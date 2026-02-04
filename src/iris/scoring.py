"""Central scoring engine for IRIS."""

from __future__ import annotations

from typing import Any

from iris.models import AnalyzerResult, AnalyzerStatus, FeedResult, RiskCategory


def calculate_score(
    results: list[AnalyzerResult],
    feed_results: list[FeedResult],
    config: dict[str, Any],
) -> tuple[float, RiskCategory]:
    """Aggregate analyzer results into a 0-100 score and risk category.

    Uses weighted aggregation with dynamic weight redistribution when
    analyzers are skipped or errored. Threat feed matches override the
    score to at least the confirmed-phishing threshold.

    Args:
        results: List of AnalyzerResult from all analyzers.
        feed_results: List of FeedResult from threat feed checks.
        config: The loaded configuration dictionary.

    Returns:
        Tuple of (overall_score, risk_category).
    """
    completed = [r for r in results if r.status == AnalyzerStatus.COMPLETED]

    if not completed:
        has_match = any(fr.matched for fr in feed_results)
        if has_match:
            return 100.0, RiskCategory.CONFIRMED_PHISHING
        return 0.0, RiskCategory.SAFE

    total_weight = sum(r.max_weight for r in completed)
    overall_score = 0.0

    for result in completed:
        normalized_weight = result.max_weight / total_weight
        overall_score += result.score * normalized_weight

    # Threat feed override: a positive match guarantees CONFIRMED_PHISHING.
    # The numeric score must also be high enough that it doesn't contradict
    # the category label — a "Confirmed Phishing" at 28 looks wrong.
    has_feed_match = any(fr.matched for fr in feed_results)

    if has_feed_match:
        # A feed match confirms malicious intent.  We boost the analyzer-
        # derived score so the final number reflects both the feed evidence
        # AND the analyzer findings, producing natural variation between
        # different phishing URLs instead of a flat constant.
        #
        # Strategy:
        #   1. Scale up the raw analyzer score into the 60-95 band so that
        #      analysers with more findings score visibly higher.
        #   2. Add a per-feed bonus (+5 each) to differentiate URLs caught
        #      by multiple feeds vs. a single feed.
        #   3. Apply a floor of 70 so confirmed phishing never looks benign,
        #      but keep it low enough that the scaled score usually exceeds
        #      it, preserving real variation.
        confirmed_floor = 70.0
        match_count = sum(1 for fr in feed_results if fr.matched)
        feed_bonus = match_count * 5.0

        # Scale the raw analyzer score (typically 10-60) into the 60-95 range.
        # Formula: 60 + (raw / 100) * 35  → a raw 0 maps to 60, raw 100 to 95.
        scaled = 60.0 + (overall_score / 100.0) * 35.0
        overall_score = max(scaled + feed_bonus, confirmed_floor)

    overall_score = min(100.0, max(0.0, overall_score))
    category = determine_category(overall_score, has_feed_match, config)

    return round(overall_score, 1), category


def determine_category(
    score: float,
    has_feed_match: bool,
    config: dict[str, Any],
) -> RiskCategory:
    """Map a numeric score to a risk category.

    Args:
        score: The overall score (0-100).
        has_feed_match: Whether any threat feed returned a positive match.
        config: The loaded configuration dictionary.

    Returns:
        The corresponding RiskCategory.
    """
    if has_feed_match:
        return RiskCategory.CONFIRMED_PHISHING

    thresholds = config.get("scoring", {}).get("thresholds", {})
    safe_max = thresholds.get("safe", 25)
    suspicious_max = thresholds.get("suspicious", 50)
    likely_max = thresholds.get("likely_phishing", 75)

    if score <= safe_max:
        return RiskCategory.SAFE
    elif score <= suspicious_max:
        return RiskCategory.SUSPICIOUS
    elif score <= likely_max:
        return RiskCategory.LIKELY_PHISHING
    else:
        return RiskCategory.CONFIRMED_PHISHING
