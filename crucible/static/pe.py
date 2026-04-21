"""PE parser using the pefile library.

We extract architecture, timestamp, sections with entropy, imports, and
exports. Everything is optional: a malformed or stripped PE still returns
a best effort result rather than raising.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore


def _machine_label(machine: int) -> str:
    return {
        0x014c: "x86",
        0x8664: "x86_64",
        0x01c4: "arm",
        0xaa64: "arm64",
    }.get(machine, f"unknown (0x{machine:04x})")


def parse(path: Path) -> Dict[str, Any]:
    """Parse a PE file and return its metadata.

    If pefile is missing or the file isn't actually a PE, returns
    ``{"parsed": False, "reason": ...}``.
    """
    if pefile is None:
        return {"parsed": False, "reason": "pefile not installed"}

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        return {"parsed": False, "reason": f"not a PE file: {exc}"}
    except Exception as exc:  # unexpected, still don't crash the scan
        return {"parsed": False, "reason": f"pefile error: {exc}"}

    sections: List[Dict[str, Any]] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="replace")
        sections.append({
            "name": name,
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": section.get_entropy(),
        })

    imports: List[Dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace") if entry.dll else ""
            funcs = [
                imp.name.decode(errors="replace")
                for imp in entry.imports
                if imp.name
            ]
            imports.append({"dll": dll, "functions": funcs})

    exports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="replace"))

    result = {
        "parsed": True,
        "architecture": _machine_label(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
    }
    pe.close()
    return result
