from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).parent
load_dotenv(PROJECT_ROOT / "api.env")

import os

sys.path.insert(0, str(PROJECT_ROOT / "bind converter"))
sys.path.insert(0, str(PROJECT_ROOT / "parsing logs"))
sys.path.insert(0, str(PROJECT_ROOT / "feature extraction"))

from domain_profiling.service import DomainProfilingService
from client_profiling.schema import initialize_schema
from labeler.intel.unknown_domain_processor import UnknownDomainProcessor
from labeler.label_dataset import DNSLabeller
from labeler.config import LabelingConfig
from labeler.intel.reputation import initialize_database
from config import config as dataset_config
from dataset_generator import DatasetGenerator
from parser import DNSLogParser
from feature_extractor import FeatureExtractor
from enrichment.enrichment_manager import EnrichmentManager
from domain_persistence import DomainPersistenceManager
from client_profiling import initialize_pool, close_pool, process_query


logger = logging.getLogger("run_pipeline")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-Based DNS Threat Detection System Pipeline"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to BIND Server Info Log or directory",
    )

    parser.add_argument(
        "--dataset",
        required=True,
        help="Path where normalized dataset CSV will be generated",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path to output Feature Matrix CSV",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively process input directory",
    )

    return parser.parse_args()


def validate_paths(
    input_path: Path,
    dataset_path: Path,
    output_path: Path,
) -> None:
    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)


def main() -> int:
    configure_logging()
    initialize_database()

    start_time = time.perf_counter()

    profiling_enabled = False

    try:
        try:
            initialize_pool()
            initialize_schema() 

            domain_profiler = DomainProfilingService()
            domain_profiler.initialize_database()
            profiling_enabled = True
            logger.info("Client profiling pool initialized")
        except Exception as exc:
            profiling_enabled = False
            logger.warning("PostgreSQL profiling pool initialization failed: %s", exc)

        args = parse_arguments()

        input_path = Path(args.input).expanduser().resolve()
        dataset_path = Path(args.dataset).expanduser().resolve()
        output_path = Path(args.output).expanduser().resolve()

        validate_paths(
            input_path=input_path,
            dataset_path=dataset_path,
            output_path=output_path,
        )

        logger.info("Pipeline Started")

        # ---------------------------------------------------------
        # Dataset Generation
        # ---------------------------------------------------------

        logger.info("Dataset Generation Started")

        dataset_config.set_input_output(
            input_path=input_path,
            output_path=dataset_path,
        )

        dataset_config.live_mode = True

        generator = DatasetGenerator(dataset_config)

        generator.process_input(
            input_path=input_path,
            output_path=dataset_path,
            recursive=args.recursive,
        )

        logger.info("Dataset Generation Finished")

        # ---------------------------------------------------------
        # Dataset Labelling
        # ---------------------------------------------------------

        logger.info("DNS Dataset Labeling Started")

        labelled_dataset_path = dataset_path.parent / "labelled_dns_dataset.csv"

        labeller = DNSLabeller()
        try:
            labeller.run(
                input_path=dataset_path,
                output_path=labelled_dataset_path,
            )

        finally:
            if hasattr(labeller, "ti") and labeller.ti is not None:
                labeller.ti.close()

        logger.info("DNS Dataset Labeling Finished")

        # ---------------------------------------------------------
        # Unknown Domain Persistence
        # ---------------------------------------------------------

        logger.info("Unknown Domain Persistence Started")

        try:
            # Read the labeled dataset to extract unknown domains
            labeled_df = pd.read_csv(labelled_dataset_path)

            logger.info("Domain Profiling Started")
            domain_profile_df = domain_profiler.process_dataframe(labeled_df)
            logger.info("Domain Profiling Finished")

            # Filter for unknown domains (not found in Tranco or URLhaus)
            unknown_mask = ~labeled_df['label_reason'].str.contains(
                r'Trusted Tranco Domain|Known Malicious Domain \(URLhaus\)',
                case=False,
                na=False,
                regex=True
            )
            unknown_domains_df = labeled_df[unknown_mask]

            if not unknown_domains_df.empty:
                with DomainPersistenceManager(enable_persistence=True) as persistence:
                    stats = persistence.process_final_dataset(
                        final_df=unknown_domains_df,
                        observation_time=None  # Will use current time
                    )

                    label_config = LabelingConfig()
                    print("=" * 60)
                    print("LabelingConfig VT:", repr(label_config.VT_API_KEY))
                    print("LabelingConfig OTX:", repr(label_config.OTX_API_KEY))
                    print("Online TI Config:", label_config.get_online_ti_config())
                    print("=" * 60)

                    processor = UnknownDomainProcessor(
                        persistence=persistence,
                        config=label_config,
                    )
                    processor.process()
                    print("=" * 60)
                    print("Unknown domains dataframe size:", len(unknown_domains_df))
                    print("ti_source counts:")
                    print(unknown_domains_df["ti_source"].value_counts())
                    print("=" * 60)

                    logger.info(
                        "Persistence Stats: %d stored, %d updated, %d skipped",
                        stats.domains_stored, stats.domains_updated, stats.domains_skipped
                    )
            else:
                logger.info("No unknown domains found to persist")

        except Exception as e:
            logger.warning("Domain persistence failed: %s. Continuing pipeline.", e)

        logger.info("Unknown Domain Persistence Finished")

        # ---------------------------------------------------------
        # Parser
        # ---------------------------------------------------------

        logger.info("Parser Started")

        parser = DNSLogParser()

        result = parser.parse_file(str(labelled_dataset_path))

        records = result.records

        logger.info("Parser Finished")

        # ---------------------------------------------------------
        # Client Profiling
        # ---------------------------------------------------------

        logger.info("Client Profiling Started")

        if profiling_enabled:
            for record in records:
                if record.client_ip and record.domain:
                    try:
                        process_query(record.client_ip, record.domain)
                    except Exception as exc:
                        logger.warning("Client profiling query failed: %s", exc)
                        continue
        else:
            logger.info("Client profiling skipped (pool not initialized)")

        logger.info("Client Profiling Finished")

        # ---------------------------------------------------------
        # Enrichment
        # ---------------------------------------------------------

        logger.info("Enrichment Started")

        enricher = EnrichmentManager(
            enable_dns=True,
            enable_whois=True,
            enable_geoip=False,
            enable_asn=True,
        )

        records = enricher.enrich(records)

        logger.info("Enrichment Finished")

        # ---------------------------------------------------------
        # Feature Extraction
        # ---------------------------------------------------------

        logger.info("Feature Extraction Started")

        extractor = FeatureExtractor(
            enable_whois=False,
            enable_ip_lookup=False,
        )

        feature_df = extractor.extract(records)

        logger.info("Feature Extraction Finished")

        feature_df.to_csv(output_path, index=False)

        elapsed = time.perf_counter() - start_time

        logger.info("Pipeline Finished")

        print("=" * 60)
        print("AI-Based DNS Threat Detection Pipeline")
        print("=" * 60)
        print()
        print(f"Input Log              : {input_path}")
        print("↓")
        print("Dataset Generator")
        print("↓")
        print(dataset_path)
        print("↓")
        print("DNS Dataset Labeler")
        print("↓")
        print(labelled_dataset_path)
        print("↓")
        print("Unknown Domain Persistence")
        print("↓")
        print("Parser")
        print("↓")
        print(f"{len(records)} DNS Records")
        print("↓")
        print("Client Profiling")
        print("↓")
        print("Enrichment")
        print("↓")
        print("Feature Extractor")
        print("↓")
        print(f"Feature Matrix Shape   : {feature_df.shape}")
        print("↓")
        print(output_path)
        print()
        print(f"Valid DNS Records      : {result.success_count}")
        print(f"Processing Time        : {elapsed:.2f} seconds")
        print("=" * 60)

        return 0

    except KeyboardInterrupt:
        logger.error("Pipeline interrupted by user.")
        return 130

    except FileNotFoundError as exc:
        logger.exception(exc)
        return 2

    except Exception as exc:
        logger.exception("Pipeline failed: %s", exc)
        return 1

    finally:
        try:
            close_pool()
        except Exception as exc:
            logger.warning("Failed to close profiling pool: %s", exc)


if __name__ == "__main__":
    sys.exit(main())