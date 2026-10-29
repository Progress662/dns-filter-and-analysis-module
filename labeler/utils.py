"""
Utility functions for DNS Dataset Labeller.
"""

import math


def calculate_shannon_entropy(domain: str) -> float:
    """
    Calculate the Shannon entropy of a domain name.

    Higher entropy often indicates randomly generated
    domains (e.g., DGA-generated domains).

    Args:
        domain: Domain name.

    Returns:
        Shannon entropy as a float.
    """
    if not domain:
        return 0.0

    domain = domain.strip().lower()

    if len(domain) < 2:
        return 0.0

    domain_length = len(domain)

    char_frequency: dict[str, int] = {}

    for char in domain:
        char_frequency[char] = char_frequency.get(char, 0) + 1

    entropy = 0.0

    for count in char_frequency.values():
        probability = count / domain_length
        entropy -= probability * math.log2(probability)

    return entropy


def get_domain_parts(domain: str) -> tuple[list[str], str]:
    """
    Split a domain into subdomains and top-level domain (TLD).

    Example:
        mail.google.co.in

    Returns:
        (
            ["mail", "google"],
            "in"
        )
    """
    if not domain:
        return [], ""

    domain = domain.strip().lower()

    if not domain:
        return [], ""

    # Remove empty labels caused by consecutive dots.
    parts = [part for part in domain.split(".") if part]

    if not parts:
        return [], ""

    tld = parts[-1]

    if len(parts) > 2:
        subdomains = parts[:-2]
    elif len(parts) == 2:
        subdomains = parts[:-1]
    else:
        subdomains = parts

    return subdomains, tld