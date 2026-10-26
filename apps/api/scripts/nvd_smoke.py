from __future__ import annotations

import argparse
import asyncio
from time import perf_counter
from typing import Sequence

from app.core.config import Settings
from app.integrations.nvd.client import NVDClient, NVDClientError
from app.services.vulnerability_intelligence import VulnerabilityIntelligenceService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Perform one controlled live lookup against the official NVD API.",
    )
    parser.add_argument("cve_id", help="CVE identifier, for example CVE-2021-44228")
    return parser


async def run(cve_id: str) -> int:
    settings = Settings(NVD_MAX_RETRIES=0)
    client = NVDClient(settings)
    started = perf_counter()
    try:
        record = await VulnerabilityIntelligenceService(client).get_cve(cve_id)
    except (NVDClientError, ValueError) as error:
        elapsed = perf_counter() - started
        print(f"LIVE NOT VERIFIED: {type(error).__name__} ({elapsed:.2f}s)")
        return 2
    finally:
        await client.aclose()
    elapsed = perf_counter() - started
    print(
        "LIVE VERIFIED: "
        f"{record.cve_id} status={record.vulnerability_status!r} "
        f"metrics={len(record.cvss_metrics)} elapsed={elapsed:.2f}s"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    return asyncio.run(run(arguments.cve_id))


if __name__ == "__main__":
    raise SystemExit(main())
