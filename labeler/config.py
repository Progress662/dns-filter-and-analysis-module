from pathlib import Path
from dataclasses import dataclass, field
from typing import Any
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LABELER_DIR = PROJECT_ROOT / "labeler"
INTEL_DIR = LABELER_DIR / "intel"
DEFAULT_INPUT = PROJECT_ROOT / "parsing logs" / "normalized_dns_dataset.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "parsing logs" / "labelled_dns_dataset.csv"

@dataclass
class LabelingConfig:
    MALICIOUS_THRESHOLD: int = 100
    SUSPICIOUS_THRESHOLD: int = 35
    WHITELIST_SCORE: int = -100
    MALICIOUS_SCORE: int = 100
    PHISHING_SCORE: int = 100
    BOTNET_SCORE: int = 100
    CRYPTOMINING_SCORE: int = 80
    SUSPICIOUS_TLD_SCORE: int = 25
    HIGH_ENTROPY_SCORE: int = 25
    LONG_DOMAIN_SCORE: int = 20
    HIGH_DIGIT_RATIO_SCORE: int = 20
    MANY_SUBDOMAINS_SCORE: int = 25
    NXDOMAIN_SCORE: int = 10
    SERVFAIL_SCORE: int = 10
    RANDOM_LOOKING_SCORE: int = 30
    ENTROPY_THRESHOLD: float = 3.8
    LENGTH_THRESHOLD: int = 20
    MIN_DIGIT_RATIO_LENGTH: int = 8
    DIGIT_RATIO_THRESHOLD: float = 0.20
    MAX_SUBDOMAIN_DEPTH: int = 4
    MIN_RANDOM_LOOKING_LENGTH: int = 12
    LOW_VOWEL_RATIO: float = 0.25
    MAX_CONSONANT_RUN: int = 5
    RANDOM_DIGIT_RATIO: float = 0.20
    RANDOM_REPEATED_CHARS: int = 1
    RANDOM_LENGTH: int = 15
    RANDOM_LOOKING_SIGNAL_THRESHOLD: int = 3
    SUSPICIOUS_TLD_FILE: Path = INTEL_DIR / "suspicious_tlds.txt"
    SUSPICIOUS_QUERY_TYPES: tuple[str, ...] = ("ANY", "NULL", "TXT")
    SUSPICIOUS_QUERY_TYPE_SCORE: int = 15
    MAX_REASON_LENGTH: int = 150
    OUTPUT_COLUMNS: tuple[str, ...] = ("threat_score", "label", "confidence", "label_reason", "ti_source")
    MIN_THREAT_SCORE: int = 0
    MAX_THREAT_SCORE: int = 100
    INTEL_SOURCES: dict[str, dict[str, Any]] = field(default_factory=dict)
    ENABLE_VT: bool = True
    ENABLE_OTX: bool = True
    VT_API_KEY: str = field(
        default_factory=lambda: os.getenv("VT_API_KEY", "")
    )
    OTX_API_KEY: str = field(
        default_factory=lambda: os.getenv("OTX_API_KEY", "")
    )
    VT_API_KEYS: list[str] = field(default_factory=lambda: [k.strip() for k in os.getenv("VT_API_KEYS", "").split(",") if k.strip()])
    OTX_API_KEYS: list[str] = field(default_factory=lambda: [k.strip() for k in os.getenv("OTX_API_KEYS", "").split(",") if k.strip()])
    WEIGHT_VT: float = 0.60
    WEIGHT_OTX: float = 0.40
    CACHE_TTL_MALICIOUS: int = 24
    CACHE_TTL_CLEAN: int = 6
    MALICIOUS_THRESHOLD_ONLINE: float = 0.60

    def has_multiple_vt_keys(self) -> bool:
        return bool(self.VT_API_KEYS)

    def has_multiple_otx_keys(self) -> bool:
        return bool(self.OTX_API_KEYS)

    def get_online_ti_config(self) -> dict[str, Any]:
        total = self.WEIGHT_VT + self.WEIGHT_OTX
        vt_w = self.WEIGHT_VT / total if total > 0 else self.WEIGHT_VT
        otx_w = self.WEIGHT_OTX / total if total > 0 else self.WEIGHT_OTX
        return {
            "ENABLE_VT": self.ENABLE_VT,
            "ENABLE_OTX": self.ENABLE_OTX,
            "VT_API_KEY": self.VT_API_KEY,
            "OTX_API_KEY": self.OTX_API_KEY,
            "VT_API_KEYS": self.VT_API_KEYS,
            "OTX_API_KEYS": self.OTX_API_KEYS,
            "WEIGHT_VT": vt_w,
            "WEIGHT_OTX": otx_w,
            "CACHE_TTL_MALICIOUS": self.CACHE_TTL_MALICIOUS,
            "CACHE_TTL_CLEAN": self.CACHE_TTL_CLEAN,
            "MALICIOUS_THRESHOLD": self.MALICIOUS_THRESHOLD_ONLINE,
        }

    def __post_init__(self) -> None:
        if self.CACHE_TTL_MALICIOUS <= 0:
            raise ValueError("CACHE_TTL_MALICIOUS must be > 0")
        if self.CACHE_TTL_CLEAN <= 0:
            raise ValueError("CACHE_TTL_CLEAN must be > 0")
        if not (0 <= self.MALICIOUS_THRESHOLD_ONLINE <= 1):
            raise ValueError("MALICIOUS_THRESHOLD_ONLINE must be between 0 and 1")
        if self.WEIGHT_VT < 0 or self.WEIGHT_OTX < 0:
            raise ValueError("Weights must be non-negative")
        if self.WEIGHT_VT == 0 and self.WEIGHT_OTX == 0:
            raise ValueError("At least one weight must be > 0")
        total = self.WEIGHT_VT + self.WEIGHT_OTX
        if total > 0:
            self.WEIGHT_VT = self.WEIGHT_VT / total
            self.WEIGHT_OTX = self.WEIGHT_OTX / total
        if self.INTEL_SOURCES:
            return
        self.INTEL_SOURCES = {
            "malicious": {"filepath": INTEL_DIR / "malicious_domains.txt", "score": self.MALICIOUS_SCORE, "reason": "Threat Intelligence: Malicious Domain"},
            "phishing": {"filepath": INTEL_DIR / "phishing_domains.txt", "score": self.PHISHING_SCORE, "reason": "Threat Intelligence: Phishing Domain"},
            "botnet": {"filepath": INTEL_DIR / "botnet_domains.txt", "score": self.BOTNET_SCORE, "reason": "Threat Intelligence: Botnet Domain"},
            "cryptomining": {"filepath": INTEL_DIR / "cryptomining_domains.txt", "score": self.CRYPTOMINING_SCORE, "reason": "Threat Intelligence: Cryptomining Domain"},
        }
