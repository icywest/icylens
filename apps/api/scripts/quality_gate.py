from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class QualityCheck:
    labels: tuple[str, ...]
    arguments: tuple[str, ...]


QUALITY_CHECKS = (
    QualityCheck(("Ruff lint",), ("-m", "ruff", "check", ".")),
    QualityCheck(("Ruff format",), ("-m", "ruff", "format", "--check", ".")),
    QualityCheck(("mypy",), ("-m", "mypy")),
    QualityCheck(
        ("pytest", "coverage"),
        (
            "-m",
            "pytest",
            "--cov=app",
            "--cov-branch",
            "--cov-report=term-missing",
            "--cov-report=html",
            "--cov-report=xml",
        ),
    ),
    QualityCheck(("pip check",), ("-m", "pip", "check")),
)


def run_check(check: QualityCheck) -> int:
    command = (sys.executable, *check.arguments)
    print(f"\n==> {' + '.join(check.labels)}", flush=True)
    print(f"    {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
    status = "PASS" if completed.returncode == 0 else "FAIL"
    for label in check.labels:
        print(f"[{status}] {label}", flush=True)
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the mandatory iCYLENS backend quality gates.",
    )
    parser.add_argument(
        "--self-test-failure",
        action="store_true",
        help="Run a harmless failing child command to verify exit propagation.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    checks: Sequence[QualityCheck] = QUALITY_CHECKS
    if arguments.self_test_failure:
        checks = (
            QualityCheck(
                ("failure propagation self-test",),
                ("-c", "raise SystemExit(7)"),
            ),
        )

    first_failure = 0
    for check in checks:
        return_code = run_check(check)
        if return_code != 0 and first_failure == 0:
            first_failure = return_code

    final_status = "PASS" if first_failure == 0 else "FAIL"
    print(f"\nQUALITY GATE: {final_status}", flush=True)
    return first_failure


if __name__ == "__main__":
    raise SystemExit(main())
