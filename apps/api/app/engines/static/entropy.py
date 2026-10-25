import math


class EntropyAccumulator:
    """Incremental byte histogram with constant memory usage."""

    def __init__(self) -> None:
        self._frequencies: list[int] = [0] * 256
        self.total_bytes = 0

    def update(self, chunk: bytes) -> None:
        for value in chunk:
            self._frequencies[value] += 1
        self.total_bytes += len(chunk)

    def shannon_entropy(self) -> float:
        if self.total_bytes == 0:
            raise ValueError("entropy is undefined for empty input")

        entropy = -math.fsum(
            (count / self.total_bytes) * math.log2(count / self.total_bytes)
            for count in self._frequencies
            if count
        )
        return min(8.0, max(0.0, entropy))
