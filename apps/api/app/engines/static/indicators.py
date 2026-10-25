import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.engines.static.strings import ExtractedString
from app.schemas.content_inspection import IndicatorCategory, StaticIndicator

URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{0,191}",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
EXECUTABLE_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,64}\.(?:exe|dll)\b", re.IGNORECASE)
SCRIPT_PATTERN = re.compile(
    r"[A-Za-z0-9_.-]{1,64}\.(?:ps1|bat|cmd|vbs|js|py)\b",
    re.IGNORECASE,
)
EVIDENCE_MAX_LENGTH = 96


@dataclass(frozen=True)
class LiteralRule:
    id: str
    category: IndicatorCategory
    description: str
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class IndicatorScanResult:
    indicators: tuple[StaticIndicator, ...]
    truncated: bool


LITERAL_RULES = (
    LiteralRule(
        "command.powershell_reference",
        "command",
        "PowerShell textual reference observed; no execution is implied",
        ("powershell", "pwsh"),
    ),
    LiteralRule(
        "command.interpreter_reference",
        "command",
        "Command-interpreter textual reference observed; no execution is implied",
        ("cmd.exe", "command.com"),
    ),
    LiteralRule(
        "command.encoded_command_token",
        "command",
        "Encoded-command option token observed",
        ("-encodedcommand", "-enc"),
    ),
)


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname or "[redacted-host]"
        suffix = "/[redacted]" if parsed.path or parsed.query or parsed.fragment else ""
    except ValueError:
        scheme = value.partition(":")[0].lower() or "http"
        host = "[redacted-host]"
        suffix = "/[redacted]"
    return f"{scheme}://{host}{suffix}"[:EVIDENCE_MAX_LENGTH]


def _redact_ipv4(value: str) -> str:
    octets = value.split(".")
    return ".".join((*octets[:3], "[redacted]"))


def _valid_ipv4(value: str) -> bool:
    return all(int(octet) <= 255 for octet in value.split("."))


def inspect_strings(
    strings: tuple[ExtractedString, ...],
    maximum_indicators: int,
) -> IndicatorScanResult:
    if maximum_indicators <= 0:
        raise ValueError("maximum_indicators must be positive")

    indicators: list[StaticIndicator] = []
    seen: set[tuple[str, str | None]] = set()
    for extracted in strings:
        text = extracted.text
        folded = text.casefold()
        candidates: list[StaticIndicator] = []

        for match in URL_PATTERN.finditer(text):
            candidates.append(
                StaticIndicator(
                    id="network.url_candidate",
                    category="network",
                    description="URL-like printable ASCII pattern observed",
                    source="printable_ascii",
                    offset=extracted.offset + match.start(),
                    evidence=_redact_url(match.group(0)),
                )
            )

        for match in IPV4_PATTERN.finditer(text):
            value = match.group(0)
            if _valid_ipv4(value):
                candidates.append(
                    StaticIndicator(
                        id="network.ipv4_candidate",
                        category="network",
                        description="Syntactically valid IPv4 address candidate observed",
                        source="printable_ascii",
                        offset=extracted.offset + match.start(),
                        evidence=_redact_ipv4(value),
                    )
                )

        for rule in LITERAL_RULES:
            matched_ranges: list[tuple[int, int]] = []
            for token in rule.tokens:
                start = folded.find(token)
                while start != -1:
                    end = start + len(token)
                    if not any(
                        start < matched_end and end > matched_start
                        for matched_start, matched_end in matched_ranges
                    ):
                        candidates.append(
                            StaticIndicator(
                                id=rule.id,
                                category=rule.category,
                                description=rule.description,
                                source="printable_ascii",
                                offset=extracted.offset + start,
                                evidence=token,
                            )
                        )
                        matched_ranges.append((start, end))
                    start = folded.find(token, start + len(token))

        for pattern, indicator_id, description, evidence in (
            (
                EXECUTABLE_PATTERN,
                "file.executable_reference",
                "Executable-related filename reference observed",
                "executable extension",
            ),
            (
                SCRIPT_PATTERN,
                "file.script_reference",
                "Script-related filename reference observed",
                "script extension",
            ),
        ):
            for match in pattern.finditer(text):
                candidates.append(
                    StaticIndicator(
                        id=indicator_id,
                        category="file",
                        description=description,
                        source="printable_ascii",
                        offset=extracted.offset + match.start(),
                        evidence=evidence,
                    )
                )

        candidates.sort(key=lambda indicator: (indicator.offset or 0, indicator.id))
        for candidate in candidates:
            key = (candidate.id, candidate.evidence)
            if key in seen:
                continue
            if len(indicators) == maximum_indicators:
                return IndicatorScanResult(tuple(indicators), truncated=True)
            seen.add(key)
            indicators.append(candidate)

    return IndicatorScanResult(tuple(indicators), truncated=False)
