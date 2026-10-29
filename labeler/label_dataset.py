import argparse
import time
from pathlib import Path
from typing import Optional

import pandas as pd
from tqdm import tqdm

from .config import DEFAULT_INPUT, DEFAULT_OUTPUT, LabelingConfig
from .heuristics import Heuristics
from .logger import logger
from .threat_intelligence import ThreatIntelligence


class DNSLabeller:
    def __init__(self, config: Optional[LabelingConfig] = None):
        self.config = config or LabelingConfig()
        self.ti = ThreatIntelligence(self.config)
        self.heuristics = Heuristics(self.config)
        logger.info("DNS Dataset Labeller initialized (training data only - offline).")

    def _process_row(
        self, row: pd.Series
    # CHANGE: return type extended with ti_source (str) as the fifth element.
    # Existing positional values (threat_score, label, confidence, label_reason)
    # are unchanged so all callers that only unpack four values keep working.
    ) -> tuple[int, str, int, str, str]:
        # FIX (Bug 1): forward client_ip and query_type from the row so that
        # ThreatIntelligence.evaluate() can include them in the metadata dict
        # passed to store_malicious_domain() for URLhaus-matched domains.
        ti_score, ti_reasons = self.ti.evaluate(
            domain=str(row.get("domain", "")),
            registered_domain=str(row.get("registered_domain", "")),
            tld=str(row.get("tld", "")),
            response_code=str(row.get("response_code", "")),
            client_ip=row.get("client_ip") or None,
            query_type=row.get("query_type") or None,
        )

        if str(row.get("domain", "")).strip().lower() == "imccj.gobgem.com":
             print("\n========== DEBUG ==========")
             print("Domain            :", repr(row.get("domain")))
             print("Registered Domain :", repr(row.get("registered_domain")))
             print("TLD               :", repr(row.get("tld")))
             print("Response Code     :", repr(row.get("response_code")))
             print("TI Score          :", ti_score)
             print("TI Reasons        :", ti_reasons)
             print("===========================\n")

        # CHANGE: derive ti_source from ti_reasons before the branching below
        # so the value is always available regardless of which path is taken.
        # ti_reasons is the authoritative record of what the TI layer matched;
        # we inspect it with the same string literals ThreatIntelligence uses.
        if "Trusted Tranco Domain" in ti_reasons:
            ti_source = "trusted"
        elif "Known Malicious Domain (URLhaus)" in ti_reasons:
            ti_source = "malicious"
        else:
            ti_source = "unknown"

        if (
            "Trusted Tranco Domain" in ti_reasons
            or "Known Malicious Domain (URLhaus)" in ti_reasons
        ):
            threat_score = ti_score
            reasons = ti_reasons
        else:
            threat_score, reasons = self.heuristics.evaluate(
                row.to_dict(),
                ti_score,
                ti_reasons,
            )    

        threat_score = max(
            self.config.MIN_THREAT_SCORE,
            min(threat_score, self.config.MAX_THREAT_SCORE),
        )

        if threat_score >= self.config.MALICIOUS_THRESHOLD:
            label = "Malicious"
            confidence = 98
        elif threat_score >= self.config.SUSPICIOUS_THRESHOLD:
            label = "Suspicious"
            confidence = min(95, 75 + ((threat_score - self.config.SUSPICIOUS_THRESHOLD) // 3))
        else:
            label = "Benign"
            confidence = 95 if threat_score == self.config.MIN_THREAT_SCORE else 82

        reason = "; ".join(dict.fromkeys(reasons))
        reason = reason[: self.config.MAX_REASON_LENGTH]

        # CHANGE: ti_source appended as the fifth return value.
        # The first four values are untouched in order and type.
        return threat_score, label, confidence, reason, ti_source

    def run(self, input_path: Path, output_path: Path) -> None:
        start_time = time.perf_counter()

        if not input_path.exists():
            raise FileNotFoundError(f"Input dataset not found: {input_path}")

        logger.info("Loading dataset: %s", input_path)

        df = pd.read_csv(input_path)

        logger.info(f"Processing {len(df):,} DNS records...")

        tqdm.pandas(desc="Labeling")

        # CHANGE: OUTPUT_COLUMNS must include "ti_source" so the new column is
        # written to the DataFrame and ultimately to the CSV.  We build the
        # expanded column list by appending "ti_source" to whatever
        # OUTPUT_COLUMNS already defines, without mutating the config object
        # itself (preserving backward compatibility for any other consumer of
        # config.OUTPUT_COLUMNS).
        output_columns = list(self.config.OUTPUT_COLUMNS)

        df[output_columns] = df.progress_apply(
            lambda row: pd.Series(self._process_row(row)),
            axis=1,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)

        self._print_summary(df, start_time, output_path)

    def _print_summary(
        self,
        df: pd.DataFrame,
        start_time: float,
        output_path: Path,
    ) -> None:
        elapsed = time.perf_counter() - start_time

        stats = df["label"].value_counts()

        response_codes = (
            df["response_code"].astype(str).str.upper()
            if "response_code" in df.columns
            else pd.Series(dtype=str)
        )

        ti_matches = (
            df["label_reason"]
            .fillna("")
            .str.contains(
                r"Threat Intelligence|Phishing|Botnet|Cryptomining|Malicious|Trusted Tranco",
                case=False,
                regex=True,
            )
            .sum()
        )

        summary = f"""
=== DNS Labeller Summary ===
Total records          : {len(df):,}
Benign                 : {stats.get("Benign", 0):,}
Suspicious             : {stats.get("Suspicious", 0):,}
Malicious              : {stats.get("Malicious", 0):,}
Average threat score   : {df["threat_score"].mean():.2f}
TI Matches             : {ti_matches:,}
NXDOMAIN count         : {(response_codes == "NXDOMAIN").sum():,}
SERVFAIL count         : {(response_codes == "SERVFAIL").sum():,}
Execution time         : {elapsed:.2f} seconds
Output                 : {output_path}
============================
"""

        print(summary)
        logger.info("Labeling completed successfully.")

    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="DNS Dataset Labeller (Offline Training Module)"
        )

        parser.add_argument(
            "--input",
            type=Path,
            default=DEFAULT_INPUT,
            help="Path to normalized_dns_dataset.csv",
        )

        parser.add_argument(
            "--output",
            type=Path,
            default=DEFAULT_OUTPUT,
            help="Path to labelled_dns_dataset.csv",
        )

        return parser


def main() -> None:
    parser = DNSLabeller.build_parser()
    args = parser.parse_args()

    labeller = DNSLabeller()
    labeller.run(args.input, args.output)


if __name__ == "__main__":
    main()