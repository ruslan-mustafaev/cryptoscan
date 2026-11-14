"""Minimal ELF / PE section parsers used to map file offsets to virtual addresses."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Section:
    name: str
    file_offset: int
    file_size: int
    vaddr: int

    def contains(self, offset: int) -> bool:
        return self.file_offset <= offset < self.file_offset + self.file_size


@dataclass(frozen=True)
class BinaryLayout:
    fmt: str               # "ELF", "PE" or "raw"
    sections: List[Section]

    def locate(self, offset: int) -> Optional[Section]:
        for section in self.sections:
            if section.contains(offset):
                return section
        return None

    def vaddr(self, offset: int) -> Optional[int]:
        section = self.locate(offset)
        if section is None:
            return None
        return section.vaddr + (offset - section.file_offset)


RAW = BinaryLayout("raw", [])


def _cstr(data: bytes, start: int) -> str:
    end = data.find(b"\x00", start)
    if end == -1:
        end = len(data)
    return data[start:end].decode("latin-1")


def parse_elf(data: bytes) -> Optional[BinaryLayout]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        if is64:
            shoff, = struct.unpack_from(endian + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from(endian + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        if shoff == 0 or shnum == 0 or shoff + shnum * shentsize > len(data):
            return BinaryLayout("ELF", [])

        raw = []
        for i in range(shnum):
            base = shoff + i * shentsize
            if is64:
                name_off, sh_type, _flags, addr, offset, size = struct.unpack_from(
                    endian + "IIQQQQ", data, base)
            else:
                name_off, sh_type, _flags, addr, offset, size = struct.unpack_from(
                    endian + "IIIIII", data, base)
            raw.append((name_off, sh_type, addr, offset, size))

        strtab_off = raw[shstrndx][3] if shstrndx < len(raw) else 0
        sections = []
        for name_off, sh_type, addr, offset, size in raw:
            if sh_type == 8 or size == 0:  # SHT_NOBITS (.bss) has no file data
                continue
            name = _cstr(data, strtab_off + name_off) if strtab_off else ""
            sections.append(Section(name, offset, size, addr))
        return BinaryLayout("ELF", sections)
    except struct.error:
        return BinaryLayout("ELF", [])


def parse_pe(data: bytes) -> Optional[BinaryLayout]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe_off, = struct.unpack_from("<I", data, 0x3C)
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        num_sections, = struct.unpack_from("<H", data, pe_off + 6)
        opt_size, = struct.unpack_from("<H", data, pe_off + 20)
        opt_off = pe_off + 24
        magic, = struct.unpack_from("<H", data, opt_off)
        if magic == 0x20B:   # PE32+
            image_base, = struct.unpack_from("<Q", data, opt_off + 24)
        else:                # PE32
            image_base, = struct.unpack_from("<I", data, opt_off + 28)

        sections = []
        table = opt_off + opt_size
        for i in range(num_sections):
            base = table + i * 40
            name = data[base:base + 8].rstrip(b"\x00").decode("latin-1")
            virt_addr, raw_size, raw_ptr = struct.unpack_from("<III", data, base + 12)
            if raw_size == 0:
                continue
            sections.append(Section(name, raw_ptr, raw_size, image_base + virt_addr))
        return BinaryLayout("PE", sections)
    except struct.error:
        return BinaryLayout("PE", [])


def detect_layout(data: bytes) -> BinaryLayout:
    return parse_elf(data) or parse_pe(data) or RAW
