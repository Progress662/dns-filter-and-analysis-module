from pathlib import Path
from typing import Dict, List, Optional


from .intel.manager import is_trusted
from .intel.malicious import is_malicious
from labeler.intel.reputation import store_malicious_domain
from .intel import ThreatIntelligence as OnlineThreatIntelligence
from labeler.intel.reputation import get_domain


from .config import INTEL_DIR, LabelingConfig
from .logger import logger


class ThreatIntelligence:

    def __init__(self, config: LabelingConfig):
        self.config = config
        self.sets: dict[str, set[str]] = {}
        self.suspicious_tlds: set[str] = set()
        self._load_all_intel()
        self.online_intel = OnlineThreatIntelligence(
            config=self.config.get_online_ti_config(),
            db_store=store_malicious_domain,
            db_getter=get_domain,
        )
        logger.info("Threat Intelligence module initialized (offline mode).")

    def _load_file(self, filepath: Path) -> set[str]:
        if not filepath.exists():
            logger.warning("Intel file missing: %s", filepath.name)
            return set()


        try:
            with filepath.open("r", encoding="utf-8") as file:
                return {
                    line.strip().lower()
                    for line in file
                    if line.strip()
                    and not line.lstrip().startswith(("#", "//"))
                }
        except Exception:
            logger.exception("Failed to load %s", filepath.name)
            return set()

    def _load_all_intel(self) -> None:
        for source_name, info in self.config.INTEL_SOURCES.items():
            # Trusted domains are handled by the SQLite-backed Tranco database.
            if source_name == "whitelist":
                continue


            self.sets[source_name] = self._load_file(info["filepath"])


        self.suspicious_tlds = self._load_file(
            self.config.SUSPICIOUS_TLD_FILE
        )


        total_entries = sum(len(entries) for entries in self.sets.values())


        logger.info(
            "Loaded %d threat intelligence entries from local files.",
            total_entries,
        )

    def evaluate(
        self,
        domain: str,
        registered_domain: str,
        tld: str,
        response_code: str,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> tuple[int, list[str]]:


        score = 0
        reasons: list[str] = []


        # Tranco stores root/registered domains (e.g. "google.com"), so the
        # registered_domain is the correct key for trusted lookups.
        tranco_lookup = (registered_domain or domain or "").strip().lower()


        # URLhaus stores full hostnames (e.g. "imccj.gobgem.com"), so we must
        # check the exact queried domain first.  If that misses, fall back to
        # the registered domain to catch cases where the root domain itself is
        # listed (e.g. a single-label or apex malicious domain).
        full_domain = (domain or "").strip().lower()
        rd_lookup = (registered_domain or "").strip().lower()


        tld = (tld or "").strip().lower()
        response_code = (response_code or "").strip().upper()


        # ------------------------------------------------------------------
        # Trusted Database (Tranco)
        # ------------------------------------------------------------------
        if tranco_lookup and is_trusted(tranco_lookup):
            return (
                self.config.WHITELIST_SCORE,
                ["Trusted Tranco Domain"],
            )


        # ------------------------------------------------------------------
        # Malicious Database (URLhaus)
        # ------------------------------------------------------------------
        # Evaluate each lookup exactly once so the database is not queried
        # more than necessary.  The results are reused for the debug prints,
        # the branch condition, and the domain selection below.
        full_match = full_domain and is_malicious(full_domain)
        root_match = (
            rd_lookup
            and rd_lookup != full_domain
            and is_malicious(rd_lookup)
        )


        print(f"\n[DEBUG] full_domain={full_domain}")
        print(f"[DEBUG] rd_lookup={rd_lookup}")
        print(f"[DEBUG] full_match={full_match}")
        print(f"[DEBUG] root_match={root_match}")


        if full_match or root_match:
            malicious_domain = full_domain if full_match else rd_lookup

            # FIX (Bug 1): include client_ip and query_type in the metadata
            # dict so that reputation_domains.client_ip / query_type are
            # populated rather than left NULL for URLhaus-matched domains.
            urlhaus_metadata: dict = {
                "source": "URLHaus",
                "confidence": 1.0,
            }
            if client_ip is not None:
                urlhaus_metadata["client_ip"] = client_ip
            if query_type is not None:
                urlhaus_metadata["query_type"] = query_type

            store_malicious_domain(
                malicious_domain,
                urlhaus_metadata,
            )


            return (
                self.config.MAX_THREAT_SCORE,
                ["Known Malicious Domain (URLhaus)"],
            )


        # ------------------------------------------------------------------
        # Legacy offline intelligence files
        # ------------------------------------------------------------------
        for source_name, info in self.config.INTEL_SOURCES.items():
            if source_name == "whitelist":
                continue


            if tranco_lookup and tranco_lookup in self.sets.get(source_name, set()):
                score += info["score"]
                reasons.append(info["reason"])
                break


        # ------------------------------------------------------------------
        # Suspicious TLD
        # ------------------------------------------------------------------
        if tld and tld in self.suspicious_tlds:
            score += self.config.SUSPICIOUS_TLD_SCORE
            reasons.append("Suspicious TLD")


        # ------------------------------------------------------------------
        # DNS Response Code
        # ------------------------------------------------------------------
        if response_code == "NXDOMAIN":
            score += self.config.NXDOMAIN_SCORE
            reasons.append("NXDOMAIN")
        elif response_code == "SERVFAIL":
            score += self.config.SERVFAIL_SCORE
            reasons.append("SERVFAIL")

        return score, reasons

    def close(self) -> None:
        """Release online threat intelligence resources."""
        self.online_intel.close()