from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

import pandas as pd


@dataclass
class DNSRecord:
    """Minimal DNS record produced by the upstream parser."""
    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str        
    response_code: str     
    resolved_ip: str       
    ttl: int               

from feature_extractor import FeatureExtractor

def build_sample_records() -> list[DNSRecord]:
    """
    Create realistic sample DNS records that demonstrate how
    the 25 features distinguish different traffic patterns.
    """
    now = datetime.now()
    records: list[DNSRecord] = []

    for i in range(30):
        records.append(DNSRecord(
            timestamp=now - timedelta(minutes=60 - i * 2),
            client_ip=f"192.168.1.{10 + (i % 5)}",
            domain="www.google.com",
            query_type="A",
            response_code="NOERROR",
            resolved_ip="142.250.77.99" if i < 25 else "142.250.77.100",
            ttl=300,
        ))

    dga_domain = "xk3jf9a2b1lq8mz.example.xyz"
    for i in range(200):
        response = "NXDOMAIN" if i < 180 else "NOERROR"
        ip = "0.0.0.0" if response == "NXDOMAIN" else "10.0.0.50"
        records.append(DNSRecord(
            timestamp=now - timedelta(minutes=10 - i * 0.05),
            client_ip=f"10.0.0.{1 + (i % 20)}",       
            domain=dga_domain,
            query_type="A",
            response_code=response,
            resolved_ip=ip,
            ttl=60,                                      
        ))

    for i in range(15):
        records.append(DNSRecord(
            timestamp=now - timedelta(minutes=30 - i),
            client_ip=f"172.16.0.{5 + (i % 3)}",
            domain="update-windows-security.com",
            query_type="A",
            response_code="NOERROR",
            resolved_ip="45.77.66.11",
            ttl=120,
        ))

    for i in range(8):
        records.append(DNSRecord(
            timestamp=now - timedelta(minutes=20 - i * 2),
            client_ip=f"192.168.1.{100 + i}",
            domain="short.io",
            query_type="A",
            response_code="NOERROR",
            resolved_ip="185.199.108.153",
            ttl=600,
        ))

    return records

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    print("=" * 70)
    print("  DNS Threat Detection — Feature Extraction Engine")
    print("=" * 70)

    records = build_sample_records()
    print(f"\n[+] Built {len(records)} sample DNS records "
          f"across {len({r.domain for r in records})} domains.\n")

    extractor = FeatureExtractor(
        enable_whois=False,
        enable_ip_lookup=False,
    )

    df = extractor.extract(records)

    pd.set_option("display.max_columns", 30)
    pd.set_option("display.width", 200)
    pd.set_option("display.float_format", "{:.2f}".format)
    print(df.to_string(index=False))

    csv_path = "data/extracted_features.csv"
    df.to_csv(csv_path, index=False)
    print(f"\n[✓] Feature dataset saved to {csv_path}")
    print(f"    Shape: {df.shape[0]} rows × {df.shape[1]} columns\n")

    print("Feature columns:")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i:>2}. {col}")


if __name__ == "__main__":
    main()