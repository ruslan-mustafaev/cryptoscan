"""cryptoscan - find cryptographic constants in binaries."""

__version__ = "1.0.0"

from .scanner import Match, scan_bytes, scan_file  # noqa: E402
from .signatures import SIGNATURES, Signature  # noqa: E402

__all__ = ["Match", "Signature", "SIGNATURES", "scan_bytes", "scan_file", "__version__"]
