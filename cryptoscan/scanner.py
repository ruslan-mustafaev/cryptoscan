"""Core scanning logic."""

from __future__ import annotations

import mmap
import os
from dataclasses import asdict, dataclass
from typing import Iterable, Iterator, List, Optional, Sequence

from .binfmt import detect_layout
from .signatures import SIGNATURES, Signature

CONFIDENCE_ORDER = {"medium": 0, "high": 1}


@dataclass(frozen=True)
class Match:
    path: str
    offset: int
    vaddr: Optional[int]
    section: Optional[str]
    name: str
    algorithm: str
    endian: str
    confidence: str
    length: int

    def to_dict(self) -> dict:
        return asdict(self)


def _find_all(buf, pattern: bytes) -> Iterator[int]:
    start = 0
    while True:
        idx = buf.find(pattern, start)
        if idx == -1:
            return
        yield idx
        start = idx + 1


def scan_bytes(data, path: str = "<memory>",
               signatures: Sequence[Signature] = SIGNATURES,
               min_confidence: str = "medium") -> List[Match]:
    """Scan a bytes-like object (bytes or mmap) for all signatures."""
    threshold = CONFIDENCE_ORDER[min_confidence]
    # bytes and mmap both support slicing, find() and struct.unpack_from(),
    # so the header parsers work on the buffer without copying it.
    layout = detect_layout(data)

    matches: List[Match] = []
    for sig in signatures:
        if CONFIDENCE_ORDER[sig.confidence] < threshold:
            continue
        for offset in _find_all(data, sig.pattern):
            section = layout.locate(offset)
            matches.append(Match(
                path=path,
                offset=offset,
                vaddr=layout.vaddr(offset),
                section=section.name if section else None,
                name=sig.name,
                algorithm=sig.algorithm,
                endian=sig.endian,
                confidence=sig.confidence,
                length=len(sig.pattern),
            ))
    matches.sort(key=lambda m: (m.offset, m.name))
    return matches


def scan_file(path: str, min_confidence: str = "medium") -> List[Match]:
    size = os.path.getsize(path)
    if size == 0:
        return []
    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return scan_bytes(mm, path=path, min_confidence=min_confidence)


def iter_files(paths: Iterable[str], recursive: bool) -> Iterator[str]:
    for path in paths:
        if os.path.isdir(path):
            if not recursive:
                continue
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    full = os.path.join(root, name)
                    if os.path.isfile(full) and not os.path.islink(full):
                        yield full
        else:
            yield path
