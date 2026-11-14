"""Command line interface: `cryptoscan FILE [FILE ...]`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .scanner import Match, iter_files, scan_file


def _format_text(matches: List[Match], path: str) -> str:
    lines = [path]
    if not matches:
        lines.append("  no known crypto constants found")
        return "\n".join(lines)
    for m in matches:
        vaddr = f"0x{m.vaddr:08x}" if m.vaddr is not None else "-" * 10
        section = (m.section or "-")[:12]
        endian = "" if m.endian == "n/a" else f" ({m.endian.upper()})"
        lines.append(
            f"  0x{m.offset:08x}  {vaddr}  {section:<12}  "
            f"{m.name}{endian}  [{m.confidence}]"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoscan",
        description="Find well-known cryptographic constants (AES, SHA-2, MD5, CRC-32, "
                    "ChaCha20, Blowfish, ...) in binaries, firmware and memory dumps.",
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="scan directories recursively")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument("--min-confidence", choices=("medium", "high"), default="medium",
                        help="hide matches below this confidence (default: medium)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not print files without matches")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code = 0
    results = []
    for path in iter_files(args.paths, args.recursive):
        if not os.path.isfile(path):
            print(f"cryptoscan: {path}: not a file (use -r for directories)", file=sys.stderr)
            exit_code = 2
            continue
        try:
            matches = scan_file(path, min_confidence=args.min_confidence)
        except OSError as exc:
            print(f"cryptoscan: {path}: {exc.strerror}", file=sys.stderr)
            exit_code = 2
            continue
        if args.json:
            results.extend(m.to_dict() for m in matches)
        elif matches or not args.quiet:
            print(_format_text(matches, path))
    if args.json:
        print(json.dumps(results, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
