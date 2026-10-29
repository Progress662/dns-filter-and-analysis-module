from __future__ import annotations

from typing import Any

from .config import LabelingConfig
from .utils import calculate_shannon_entropy, get_domain_parts


class ScoringEngine:
    def __init__(self, config: LabelingConfig):
        self.config = config

    @staticmethod
    def _extract_sld(domain: str) -> str:
        if not domain:
            return ""

        parts = domain.split(".")

        if len(parts) < 2:
            return parts[0] if parts else ""

        return parts[-2]

    @staticmethod
    def _vowel_ratio(label: str) -> float:
        if not label:
            return 0.0

        vowels = sum(1 for char in label if char in "aeiou")
        return vowels / len(label)

    @staticmethod
    def _max_consonant_run(label: str) -> int:
        if not label:
            return 0

        max_run = 0
        current_run = 0

        for char in label:
            if char.isalpha() and char not in "aeiou":
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
            else:
                current_run = 0

        return max_run

    @staticmethod
    def _repeated_character_count(label: str) -> int:
        if not label:
            return 0

        repeated = 0
        previous_char: str | None = None

        for char in label:
            if char == previous_char and char.isalnum():
                repeated += 1
            previous_char = char

        return repeated

    def _entropy(self, domain: str) -> tuple[int, str]:
        if not domain:
            return 0, ""

        sld = self._extract_sld(domain)

        if not sld:
            return 0, ""

        entropy = calculate_shannon_entropy(sld)

        if entropy >= self.config.ENTROPY_THRESHOLD:
            return self.config.HIGH_ENTROPY_SCORE, "High Entropy"

        return 0, ""

    def _length(self, domain: str) -> tuple[int, str]:
        if not domain:
            return 0, ""

        sld = self._extract_sld(domain)

        if not sld:
            return 0, ""

        if len(sld) >= self.config.LENGTH_THRESHOLD:
            return self.config.LONG_DOMAIN_SCORE, "Excessive Length"

        return 0, ""

    def _digit_ratio(self, domain: str) -> tuple[int, str]:
        if not domain:
            return 0, ""

        sld = self._extract_sld(domain)

        if not sld or len(sld) < self.config.MIN_DIGIT_RATIO_LENGTH:
            return 0, ""

        digits = sum(char.isdigit() for char in sld)
        ratio = digits / len(sld)

        if ratio >= self.config.DIGIT_RATIO_THRESHOLD:
            return self.config.HIGH_DIGIT_RATIO_SCORE, "High Digit Ratio"

        return 0, ""

    def _subdomains(self, domain: str) -> tuple[int, str]:
        if not domain:
            return 0, ""

        subdomains, _ = get_domain_parts(domain)

        if len(subdomains) >= self.config.MAX_SUBDOMAIN_DEPTH:
            return self.config.MANY_SUBDOMAINS_SCORE, "Many Subdomains"

        return 0, ""

    def _random_looking(self, domain: str) -> tuple[int, str]:
        if not domain:
            return 0, ""

        sld = self._extract_sld(domain)

        if not sld or len(sld) < self.config.MIN_RANDOM_LOOKING_LENGTH:
            return 0, ""

        entropy = calculate_shannon_entropy(sld)
        vowel_ratio = self._vowel_ratio(sld)
        consonant_run = self._max_consonant_run(sld)
        digit_ratio = sum(char.isdigit() for char in sld) / len(sld)
        repeated_chars = self._repeated_character_count(sld)
        length = len(sld)

        signals = 0
        triggered_reasons: list[str] = []

        if entropy >= self.config.ENTROPY_THRESHOLD:
            signals += 1
            triggered_reasons.append("high entropy")

        if(vowel_ratio < self.config.LOW_VOWEL_RATIO and entropy >= self.config.ENTROPY_THRESHOLD):
            signals += 1
            triggered_reasons.append("low vowel ratio")

        if consonant_run >= self.config.MAX_CONSONANT_RUN:
            signals += 1
            triggered_reasons.append("long consonant run")

        if digit_ratio >= self.config.RANDOM_DIGIT_RATIO:
            signals += 1
            triggered_reasons.append("digit presence")

        if repeated_chars <= self.config.RANDOM_REPEATED_CHARS:
            signals += 1
            triggered_reasons.append("no repeated characters")

        if length >= self.config.RANDOM_LENGTH:
            signals += 1
            triggered_reasons.append("long label")

        if signals >= self.config.RANDOM_LOOKING_SIGNAL_THRESHOLD:
            return (
                self.config.RANDOM_LOOKING_SCORE,
                f"Random-looking Domain ({', '.join(triggered_reasons)})",
            )

        return 0, ""

    def _query_type(self, query_type: str) -> tuple[int, str]:
        if (
            query_type
            and query_type.upper() in self.config.SUSPICIOUS_QUERY_TYPES
        ):
            return (
                self.config.SUSPICIOUS_QUERY_TYPE_SCORE,
                "Suspicious Query Type",
            )

        return 0, ""

    def evaluate(self, row: dict[str, Any]) -> tuple[int, list[str]]:
        domain = str(row.get("domain", "")).strip().lower()
        query_type = str(row.get("query_type", "")).strip().upper()

        heuristics = (
            self._entropy(domain),
            self._length(domain),
            self._digit_ratio(domain),
            self._subdomains(domain),
            self._random_looking(domain),
            self._query_type(query_type),
        )

        total_score = 0
        reasons: list[str] = []

        for score, reason in heuristics:
            if score > 0:
                total_score += score
                reasons.append(reason)

        return total_score, reasons


class Heuristics:
    def __init__(self, config: LabelingConfig):
        self.config = config
        self.scoring_engine = ScoringEngine(config)

    def evaluate(
        self,
        row: dict[str, Any],
        ti_score: int,
        ti_reasons: list[str],
    ) -> tuple[int, list[str]]:
        heuristic_score, heuristic_reasons = self.scoring_engine.evaluate(row)

        total_score = ti_score + heuristic_score
        total_score = max(
            self.config.MIN_THREAT_SCORE,
            min(total_score, self.config.MAX_THREAT_SCORE),
        )

        return total_score, ti_reasons + heuristic_reasons