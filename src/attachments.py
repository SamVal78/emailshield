"""
Attachment inspection for EmailShield.

A filename is a claim, not a fact. This module checks the claim three ways:

  1. Does the extension belong to a category that can execute?
  2. Do the file's leading bytes match the type the name and MIME header claim?
  3. If the file is an OOXML container, does it contain a macro project?

None of this is content scanning or malware analysis. It is the cheap structural
checking that a triage tool can do without a sandbox, and its limits are stated
in the docs rather than glossed over.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field


# Extensions that can execute directly, or that instruct another program to
# execute something. The grouping matters for scoring: a .exe in an email is a
# different proposition from a .docm.
DIRECTLY_EXECUTABLE = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "hta", "jar", "app",
    "dmg", "pkg", "deb", "rpm", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "sh", "py", "pl", "rb", "reg", "lnk", "url",
    "iso", "img", "vhd", "vhdx", "chm", "msc", "gadget",
}

MACRO_CAPABLE = {
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm",
    "xls", "doc", "ppt",          # legacy formats, macros possible
}

ARCHIVE = {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab", "ace", "arj"}

# Formats that are frequently used as the outer wrapper in phishing, not because
# they execute but because they carry a link or a further payload.
DOCUMENT = {"pdf", "docx", "xlsx", "pptx", "rtf", "one", "svg", "html", "htm"}


# Leading byte signatures. Short deliberately: the goal is catching a blatant
# mismatch, not identifying every format.
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip-container"),
    (b"PK\x05\x06", "zip-container"),
    (b"PK\x07\x08", "zip-container"),
    (b"\xd0\xcf\x11\xe0", "ole-compound"),      # legacy .doc/.xls/.msi
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "rtf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"<?xml", "xml"),
    (b"<!DOCTYPE", "html"),
    (b"<html", "html"),
]

# Which detected magic types are consistent with which extensions.
EXTENSION_EXPECTS: dict[str, set[str]] = {
    "pdf": {"pdf"},
    "docx": {"zip-container"}, "xlsx": {"zip-container"}, "pptx": {"zip-container"},
    "docm": {"zip-container"}, "xlsm": {"zip-container"}, "pptm": {"zip-container"},
    "zip": {"zip-container"},
    "doc": {"ole-compound"}, "xls": {"ole-compound"}, "ppt": {"ole-compound"},
    "exe": {"windows-executable"}, "dll": {"windows-executable"},
    "msi": {"ole-compound"},
    "rtf": {"rtf"},
    "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "png": {"png"}, "gif": {"gif"},
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "html": {"html", "xml"}, "htm": {"html", "xml"}, "svg": {"xml", "html"},
}

# Unicode direction controls. U+202E reverses the display of what follows, so a
# file actually named "invoicefdp.exe" with the control inserted displays as
# "invoiceexe.pdf" to the reader. There is no legitimate use of these in a
# filename.
BIDI_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u200f", "\u200e",
}


@dataclass
class AttachmentFinding:
    filename: str
    display_filename: str            # bidi controls stripped
    extensions: list[str]            # all extensions, e.g. ["pdf", "exe"]
    effective_extension: str
    category: str                    # "executable", "macro", "archive", "document", "other"
    declared_content_type: str
    detected_type: str               # from magic bytes, or "unknown"
    size_bytes: int
    type_mismatch: bool
    contains_macro_project: bool = False
    nested_archive_entries: list[str] = field(default_factory=list)
    has_bidi_control: bool = False
    double_extension: bool = False
    notes: list[str] = field(default_factory=list)


def _strip_bidi(name: str) -> tuple[str, bool]:
    found = any(c in BIDI_CONTROLS for c in name)
    cleaned = "".join(c for c in name if c not in BIDI_CONTROLS)
    return cleaned, found


def _detect_magic(payload: bytes) -> str:
    for signature, name in MAGIC_SIGNATURES:
        if payload.startswith(signature):
            return name
    return "unknown"


def _categorise(extension: str) -> str:
    if extension in DIRECTLY_EXECUTABLE:
        return "executable"
    if extension in MACRO_CAPABLE:
        return "macro"
    if extension in ARCHIVE:
        return "archive"
    if extension in DOCUMENT:
        return "document"
    return "other"


def _inspect_ooxml(payload: bytes) -> tuple[bool, list[str]]:
    """
    Look inside an OOXML container for a macro project.

    A .docx and a .docm are both ZIP archives. The difference is that a macro
    enabled document contains word/vbaProject.bin. Renaming a .docm to .docx does
    not remove the macro project, so the container has to be opened to tell them
    apart. Python's zipfile does this without any third-party dependency.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError, EOFError):
        return False, []

    macro_markers = [
        n for n in names
        if n.lower().endswith("vbaproject.bin") or n.lower().endswith("vbaproject.binx")
    ]
    return bool(macro_markers), names


def _list_archive(payload: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            return archive.namelist()
    except (zipfile.BadZipFile, OSError, EOFError):
        return []


def inspect_attachment(
    filename: str,
    declared_content_type: str,
    payload: bytes,
    size_bytes: int | None = None,
) -> AttachmentFinding:
    display_name, had_bidi = _strip_bidi(filename)

    pieces = display_name.split(".")
    extensions = [p.lower() for p in pieces[1:]] if len(pieces) > 1 else []
    effective = extensions[-1] if extensions else ""

    detected = _detect_magic(payload) if payload else "unknown"

    finding = AttachmentFinding(
        filename=filename,
        display_filename=display_name,
        extensions=extensions,
        effective_extension=effective,
        category=_categorise(effective),
        declared_content_type=(declared_content_type or "").lower(),
        detected_type=detected,
        size_bytes=size_bytes if size_bytes is not None else len(payload),
        type_mismatch=False,
        has_bidi_control=had_bidi,
    )

    if had_bidi:
        finding.notes.append(
            "filename contains a Unicode bidirectional control character, which "
            "makes the displayed name differ from the real one. There is no "
            f"legitimate reason for this. Real name: '{display_name}'"
        )

    # A double extension only matters when the first one is a document type the
    # reader would trust and the last one executes. "archive.tar.gz" is two
    # extensions and entirely normal.
    if len(extensions) >= 2:
        first = extensions[-2]
        if first in DOCUMENT | MACRO_CAPABLE and effective in DIRECTLY_EXECUTABLE:
            finding.double_extension = True
            finding.notes.append(
                f"double extension: displays as a .{first} but the operating system "
                f"will treat it as .{effective}"
            )

    if detected != "unknown" and effective in EXTENSION_EXPECTS:
        if detected not in EXTENSION_EXPECTS[effective]:
            finding.type_mismatch = True
            finding.notes.append(
                f"leading bytes indicate {detected} but the extension claims "
                f".{effective}. The extension is a claim by the sender; the bytes "
                "are what the file actually is."
            )

    if detected == "zip-container":
        has_macro, names = _inspect_ooxml(payload)
        finding.contains_macro_project = has_macro
        if has_macro:
            finding.notes.append(
                "container includes a VBA macro project (vbaProject.bin). A file "
                "named .docx cannot legitimately contain one."
                if effective in {"docx", "xlsx", "pptx"}
                else "container includes a VBA macro project (vbaProject.bin)"
            )
        if effective in ARCHIVE:
            finding.nested_archive_entries = names
            inner_risky = [
                n for n in names
                if n.rsplit(".", 1)[-1].lower() in DIRECTLY_EXECUTABLE | MACRO_CAPABLE
            ]
            if inner_risky:
                finding.notes.append(
                    "archive contains entries that can execute: "
                    + ", ".join(inner_risky[:5])
                )
            encrypted = _archive_is_encrypted(payload)
            if encrypted:
                finding.notes.append(
                    "archive is password protected, so its contents cannot be "
                    "inspected here and will not be scanned by most gateways either"
                )

    return finding


def _archive_is_encrypted(payload: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            return any(info.flag_bits & 0x1 for info in archive.infolist())
    except (zipfile.BadZipFile, OSError, EOFError):
        return False
