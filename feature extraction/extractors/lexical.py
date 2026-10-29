from __future__ import annotations

import math
from collections import Counter
from typing import Dict

import tldextract


class LexicalExtractor:
    """
    Computes lexical features from a domain name.

    Features:
    1. domain_length
    2. digit_count
    3. entropy
    4. hyphen_count
    5. subdomain_count
    6. vowel_ratio
    7. consonant_ratio
    8. longest_digit_seq
    9. longest_consonant_seq
    10. unique_char_count
    """

    _VOWELS = set("aeiou")
    _CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

    @staticmethod
    def extract(domain: str) -> Dict[str, float]:
        """
        Extract lexical features from a domain.

        Example:
            mail.google.com
            api.login.microsoftonline.com
            google.com
        """

        if not domain:
            return {
                "domain_length": 0.0,
                "digit_count": 0.0,
                "entropy": 0.0,
                "hyphen_count": 0.0,
                "subdomain_count": 0.0,
                "vowel_ratio": 0.0,
                "consonant_ratio": 0.0,
                "longest_digit_seq": 0.0,
                "longest_consonant_seq": 0.0,
                "unique_char_count": 0.0,
            }

        domain = domain.strip().lower()

        alpha_chars = [c for c in domain if c.isalpha()]
        alpha_count = len(alpha_chars)

        ext = tldextract.extract(domain)

        if ext.subdomain:
            subdomain_count = float(len(ext.subdomain.split(".")))
        else:
            subdomain_count = 0.0

        if alpha_count == 0:
            vowel_ratio = 0.0
            consonant_ratio = 0.0
        else:
            vowel_count = sum(
                1 for c in alpha_chars
                if c in LexicalExtractor._VOWELS
            )

            consonant_count = sum(
                1 for c in alpha_chars
                if c in LexicalExtractor._CONSONANTS
            )

            vowel_ratio = vowel_count / alpha_count
            consonant_ratio = consonant_count / alpha_count

        features = {
            "domain_length": float(len(domain)),
            "digit_count": float(sum(ch.isdigit() for ch in domain)),
            "entropy": _shannon_entropy(domain),
            "hyphen_count": float(domain.count("-")),
            "subdomain_count": subdomain_count,
            "vowel_ratio": round(vowel_ratio, 4),
            "consonant_ratio": round(consonant_ratio, 4),
            "longest_digit_seq": float(
                _longest_run(domain, lambda c: c.isdigit())
            ),
            "longest_consonant_seq": float(
                _longest_run(
                    domain,
                    lambda c: c in LexicalExtractor._CONSONANTS,
                )
            ),
            "unique_char_count": float(len(set(domain))),
        }

        return features


def _shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a string.
    """

    if not text:
        return 0.0

    counter = Counter(text)
    length = len(text)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )

    return round(entropy, 4)


def _longest_run(text: str, predicate) -> int:
    """
    Returns the longest consecutive sequence satisfying predicate.
    """

    longest = 0
    current = 0

    for ch in text:
        if predicate(ch):
            current += 1
            longest = max(longest, current)
        else:
            current = 0

    return longest