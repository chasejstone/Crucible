"""ELF parser built on the stdlib `struct` module.

Only parses the bits the report actually uses: header, program and section
headers, dynamic symbols (imports / exports). Keeps us free of an extra
dependency.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

from crucible.static.entropy import shannon

EI_MAG = b"\x7fELF"

_MACHINE = {
    0x03: "x86", 0x3e: "x86_64", 0x28: "arm", 0xb7: "aarch64",
    0x32: "ia64", 0x14: "ppc", 0x15: "ppc64", 0xf3: "riscv",
}


def _read_header(data: bytes) -> Tuple[Dict[str, Any], str, str]:
    """Parse e_ident and the main ELF header. Returns (header, fmt, bits)."""
    if not data.startswith(EI_MAG):
        raise ValueError("not an ELF file")

    ei_class = data[4]
    ei_data = data[5]
    bits = "64" if ei_class == 2 else "32"
    endian = "<" if ei_data == 1 else ">"

    if bits == "64":
        fmt = endian + "HHIQQQIHHHHHH"
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, data, 16)
        header = dict(zip(
            ("e_type", "e_machine", "e_version", "e_entry", "e_phoff",
             "e_shoff", "e_flags", "e_ehsize", "e_phentsize", "e_phnum",
             "e_shentsize", "e_shnum", "e_shstrndx"),
            vals,
        ))
    else:
        fmt = endian + "HHIIIIIHHHHHH"
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, data, 16)
        header = dict(zip(
            ("e_type", "e_machine", "e_version", "e_entry", "e_phoff",
             "e_shoff", "e_flags", "e_ehsize", "e_phentsize", "e_phnum",
             "e_shentsize", "e_shnum", "e_shstrndx"),
            vals,
        ))

    return header, endian, bits


def _section_headers(data: bytes, header: Dict[str, Any],
                     endian: str, bits: str) -> List[Dict[str, Any]]:
    """Parse all section headers and compute entropy of each section."""
    if bits == "64":
        sh_fmt = endian + "IIQQQQIIQQ"
        names = ("sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset",
                 "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize")
    else:
        sh_fmt = endian + "IIIIIIIIII"
        names = ("sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset",
                 "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize")

    n = header["e_shnum"]
    offset = header["e_shoff"]
    ent_sz = header["e_shentsize"]
    if n == 0 or offset == 0:
        return []

    # Read the string table so we can resolve section names.
    raw_headers: List[Dict[str, Any]] = []
    for i in range(n):
        chunk = data[offset + i * ent_sz: offset + i * ent_sz + struct.calcsize(sh_fmt)]
        if len(chunk) < struct.calcsize(sh_fmt):
            break
        vals = struct.unpack(sh_fmt, chunk)
        raw_headers.append(dict(zip(names, vals)))

    shstrndx = header["e_shstrndx"]
    strtab = b""
    if 0 <= shstrndx < len(raw_headers):
        sh = raw_headers[shstrndx]
        strtab = data[sh["sh_offset"]: sh["sh_offset"] + sh["sh_size"]]

    out: List[Dict[str, Any]] = []
    for sh in raw_headers:
        name_end = strtab.find(b"\x00", sh["sh_name"]) if strtab else -1
        name = (strtab[sh["sh_name"]:name_end].decode(errors="replace")
                if name_end != -1 else "")
        body = data[sh["sh_offset"]: sh["sh_offset"] + sh["sh_size"]]
        out.append({
            "name": name,
            "type": sh["sh_type"],
            "flags": sh["sh_flags"],
            "size": sh["sh_size"],
            "offset": sh["sh_offset"],
            "entropy": shannon(body),
        })
    return out


def _dynamic_symbols(data: bytes, sections: List[Dict[str, Any]],
                     endian: str, bits: str) -> Tuple[List[str], List[str]]:
    """Walk .dynsym to collect imports (undefined) and exports (defined)."""
    dynsym = next((s for s in sections if s["name"] == ".dynsym"), None)
    dynstr = next((s for s in sections if s["name"] == ".dynstr"), None)
    if not dynsym or not dynstr:
        return [], []

    strtab = data[dynstr["offset"]: dynstr["offset"] + dynstr["size"]]

    if bits == "64":
        sym_fmt = endian + "IBBHQQ"
    else:
        sym_fmt = endian + "IIIBBH"

    sym_sz = struct.calcsize(sym_fmt)
    count = dynsym["size"] // sym_sz

    imports: List[str] = []
    exports: List[str] = []
    for i in range(count):
        start = dynsym["offset"] + i * sym_sz
        chunk = data[start: start + sym_sz]
        if len(chunk) < sym_sz:
            break
        if bits == "64":
            st_name, _info, _other, st_shndx, _value, _size = struct.unpack(sym_fmt, chunk)
        else:
            st_name, _value, _size, _info, _other, st_shndx = struct.unpack(sym_fmt, chunk)

        end = strtab.find(b"\x00", st_name)
        name = strtab[st_name:end].decode(errors="replace") if end != -1 else ""
        if not name:
            continue
        if st_shndx == 0:   # SHN_UNDEF: imported from another object
            imports.append(name)
        else:
            exports.append(name)

    return imports, exports


def parse(path: Path) -> Dict[str, Any]:
    """Parse an ELF file into a metadata dict.

    Returns ``{"parsed": False, ...}`` on error so callers can keep going.
    """
    try:
        data = path.read_bytes()
        if not data.startswith(EI_MAG):
            return {"parsed": False, "reason": "not an ELF file"}

        header, endian, bits = _read_header(data)
        sections = _section_headers(data, header, endian, bits)
        imports, exports = _dynamic_symbols(data, sections, endian, bits)

        type_name = {
            1: "relocatable", 2: "executable", 3: "shared_object", 4: "core",
        }.get(header["e_type"], f"unknown({header['e_type']})")

        return {
            "parsed": True,
            "class": f"ELF{bits}",
            "endianness": "little" if endian == "<" else "big",
            "architecture": _MACHINE.get(header["e_machine"],
                                         f"unknown (0x{header['e_machine']:x})"),
            "type": type_name,
            "entry_point": header["e_entry"],
            "sections": sections,
            "imports": imports,
            "exports": exports,
        }
    except Exception as exc:
        return {"parsed": False, "reason": f"ELF parse failed: {exc}"}
