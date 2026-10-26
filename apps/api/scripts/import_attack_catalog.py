from __future__ import annotations

import argparse
import gzip
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.attack.catalog import (
    ATTACK_SOURCE_URL,
    DEFAULT_SNAPSHOT_PATH,
    ATTACKCatalogSnapshot,
    ATTACKCatalogValidationError,
    build_snapshot_from_stix,
    serialize_snapshot,
)

MAX_SOURCE_BYTES = 64 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 20.0
TOTAL_DEADLINE_SECONDS = 90.0
MAX_RETRIES = 2


class ATTACKAcquisitionError(RuntimeError):
    """The fixed official ATT&CK asset could not be acquired safely."""


def download_official_dataset() -> bytes:
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        if time.monotonic() >= deadline:
            break
        try:
            timeout = httpx.Timeout(
                connect=min(
                    CONNECT_TIMEOUT_SECONDS, max(0.1, deadline - time.monotonic())
                ),
                read=min(READ_TIMEOUT_SECONDS, max(0.1, deadline - time.monotonic())),
                write=READ_TIMEOUT_SECONDS,
                pool=CONNECT_TIMEOUT_SECONDS,
            )
            with httpx.Client(
                follow_redirects=False,
                trust_env=False,
                timeout=timeout,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "iCYLENS-ATTACK-importer/1.0",
                },
            ) as client:
                with client.stream("GET", ATTACK_SOURCE_URL) as response:
                    if 300 <= response.status_code < 400:
                        raise ATTACKAcquisitionError("Redirects are forbidden")
                    response.raise_for_status()
                    declared = response.headers.get("content-length")
                    if declared is not None and int(declared) > MAX_SOURCE_BYTES:
                        raise ATTACKAcquisitionError(
                            "Dataset exceeds declared size limit"
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes(64 * 1024):
                        if time.monotonic() >= deadline:
                            raise ATTACKAcquisitionError(
                                "Total download deadline exceeded"
                            )
                        body.extend(chunk)
                        if len(body) > MAX_SOURCE_BYTES:
                            raise ATTACKAcquisitionError(
                                "Dataset exceeds streamed size limit"
                            )
                    return bytes(body)
        except (httpx.HTTPError, ValueError, ATTACKAcquisitionError) as error:
            last_error = error
            if attempt < MAX_RETRIES and time.monotonic() < deadline:
                time.sleep(
                    min(0.5 * (2**attempt), max(0.0, deadline - time.monotonic()))
                )
    raise ATTACKAcquisitionError(
        "Official ATT&CK dataset acquisition failed"
    ) from last_error


def publish_snapshot(snapshot: ATTACKCatalogSnapshot, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    compressed = gzip.compress(serialize_snapshot(snapshot), compresslevel=9, mtime=0)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            stream.write(compressed)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def import_catalog(destination: Path = DEFAULT_SNAPSHOT_PATH) -> ATTACKCatalogSnapshot:
    source = download_official_dataset()
    snapshot = build_snapshot_from_stix(source, datetime.now(timezone.utc))
    publish_snapshot(snapshot, destination)
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import the pinned official Enterprise ATT&CK 19.2 STIX bundle"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_SNAPSHOT_PATH)
    args = parser.parse_args()
    try:
        snapshot = import_catalog(args.output.resolve())
    except (ATTACKAcquisitionError, ATTACKCatalogValidationError, OSError) as error:
        parser.error(str(error))
    print(snapshot.provenance.model_dump_json())
    print(snapshot.statistics.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
