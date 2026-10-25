from dataclasses import dataclass

from app.schemas.fingerprint import DetectedFormat

SIGNATURE_INSPECTION_BYTES = 4096
PE_OFFSET_FIELD = 0x3C
PE_OFFSET_FIELD_END = PE_OFFSET_FIELD + 4
PE_SIGNATURE = b"PE\x00\x00"


@dataclass(frozen=True)
class SignaturePattern:
    format: DetectedFormat
    name: str
    magic: bytes


@dataclass(frozen=True)
class SignatureMatch:
    format: DetectedFormat
    name: str | None = None
    offset: int | None = None
    signature: bytes | None = None


LEADING_SIGNATURES = (
    SignaturePattern("pdf", "PDF", b"%PDF-"),
    SignaturePattern("png", "PNG", b"\x89PNG\r\n\x1a\n"),
    SignaturePattern("jpeg", "JPEG", b"\xff\xd8\xff"),
    SignaturePattern("gif", "GIF87a", b"GIF87a"),
    SignaturePattern("gif", "GIF89a", b"GIF89a"),
    SignaturePattern("zip", "ZIP local file header", b"PK\x03\x04"),
    SignaturePattern("zip", "ZIP empty archive", b"PK\x05\x06"),
    SignaturePattern("zip", "ZIP data descriptor", b"PK\x07\x08"),
    SignaturePattern("elf", "ELF", b"\x7fELF"),
)


def detect_signature(header: bytes) -> SignatureMatch:
    """Identify a supported leading signature without parsing the full format."""
    for pattern in LEADING_SIGNATURES:
        if header.startswith(pattern.magic):
            return SignatureMatch(
                format=pattern.format,
                name=pattern.name,
                offset=0,
                signature=pattern.magic,
            )

    if header.startswith(b"MZ") and len(header) >= PE_OFFSET_FIELD_END:
        pe_offset = int.from_bytes(
            header[PE_OFFSET_FIELD:PE_OFFSET_FIELD_END],
            byteorder="little",
        )
        if pe_offset < 0 or pe_offset > len(header) or pe_offset < PE_OFFSET_FIELD_END:
            return SignatureMatch(format="unknown")
        signature_end = pe_offset + len(PE_SIGNATURE)
        if (
            signature_end <= len(header)
            and header[pe_offset:signature_end] == PE_SIGNATURE
        ):
            return SignatureMatch(
                format="pe",
                name="Windows PE candidate",
                offset=pe_offset,
                signature=PE_SIGNATURE,
            )

    return SignatureMatch(format="unknown")
