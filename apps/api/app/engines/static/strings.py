from dataclasses import dataclass

PRINTABLE_ASCII_MIN = 0x20
PRINTABLE_ASCII_MAX = 0x7E


@dataclass(frozen=True)
class ExtractedString:
    text: str
    offset: int
    original_length: int
    truncated: bool


@dataclass(frozen=True)
class StringExtractionResult:
    strings: tuple[ExtractedString, ...]
    observed_count: int
    truncated: bool


class PrintableStringExtractor:
    """Extract bounded printable ASCII runs while preserving stream state."""

    def __init__(
        self,
        minimum_length: int,
        maximum_strings: int,
        maximum_length: int,
    ) -> None:
        if minimum_length <= 0:
            raise ValueError("minimum_length must be positive")
        if maximum_strings <= 0:
            raise ValueError("maximum_strings must be positive")
        if maximum_length < minimum_length:
            raise ValueError("maximum_length must be at least minimum_length")

        self.minimum_length = minimum_length
        self.maximum_strings = maximum_strings
        self.maximum_length = maximum_length
        self._strings: list[ExtractedString] = []
        self._position = 0
        self._current_offset = 0
        self._current_length = 0
        self._current_text = bytearray()
        self._observed_count = 0
        self._truncated = False

    def update(self, chunk: bytes) -> None:
        for value in chunk:
            if PRINTABLE_ASCII_MIN <= value <= PRINTABLE_ASCII_MAX:
                if self._current_length == 0:
                    self._current_offset = self._position
                self._current_length += 1
                if len(self._current_text) < self.maximum_length:
                    self._current_text.append(value)
            else:
                self._finish_current()
            self._position += 1

    def finalize(self) -> StringExtractionResult:
        self._finish_current()
        return StringExtractionResult(
            strings=tuple(self._strings),
            observed_count=self._observed_count,
            truncated=self._truncated,
        )

    def _finish_current(self) -> None:
        if self._current_length >= self.minimum_length:
            self._observed_count += 1
            string_was_truncated = self._current_length > self.maximum_length
            if len(self._strings) < self.maximum_strings:
                self._strings.append(
                    ExtractedString(
                        text=self._current_text.decode("ascii"),
                        offset=self._current_offset,
                        original_length=self._current_length,
                        truncated=string_was_truncated,
                    )
                )
            else:
                self._truncated = True
            if string_was_truncated:
                self._truncated = True

        self._current_length = 0
        self._current_text.clear()
