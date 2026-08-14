"""
deepchecks — single-file combined build. All 13 working tools:
Amcache, BAM, Prefetch, MFT, Browsing History, Downloads History,
USBDeview, PowerShellParser, StringExplorer, SavedFilesViewer,
PathsParser, JournalTrace, CrashedFileViewer.
Run with: python3 deepchecks.py
"""

import ctypes, csv, os, shutil, sqlite3, struct, sys, tempfile, traceback, hashlib, json, math, re
import urllib.request, urllib.error
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import unquote, urlparse

# ======================================================================
# ---- from parsers/timeconv.py ----
# ======================================================================
"""
timeconv.py — timestamp conversions for browser artifact formats.

Chrome/Edge/Brave/Opera (all Chromium): "WebKit time" — microseconds
since 1601-01-01 00:00:00 UTC. Same epoch as a Windows FILETIME, just
microseconds instead of 100ns ticks.

Firefox (places.sqlite): PRTime — microseconds since 1970-01-01 00:00:00
UTC (the ordinary Unix epoch, just in microseconds rather than seconds).
"""


_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_time_to_datetime(us: int):
    if not us:
        return None
    try:
        return _WEBKIT_EPOCH + timedelta(microseconds=us)
    except (OverflowError, OSError):
        return None


def firefox_time_to_datetime(us: int):
    if not us:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    except (OverflowError, OSError):
        return None

# ======================================================================
# ---- from parsers/hive.py ----
# ======================================================================
"""
hive.py — minimal pure-Python Windows registry hive (regf) reader.

Implements just enough of the on-disk registry format to walk keys/subkeys
and read values, which is all Amcache.hve and SYSTEM (for BAM) parsing need.

Format reference (public, reverse-engineered documentation — the same
structure is described independently by the Registry Explorer / python-
registry / regipy / libregf projects; no source code from those projects
is used here, this is a fresh implementation against the documented
on-disk layout):

  Base block (first 4096 bytes):
    0x00  "regf"                signature
    0x24  root cell offset      relative to start of hbin data (i.e. +0x1000)
    0x28  total hive bins size

  Hive bin (hbin):
    0x00  "hbin"
    0x04  offset of this bin, relative to hbin data start
    0x08  size of this bin

  Cell: 4-byte little-endian signed size. Negative = in use; abs(size)
  is the total cell size including this 4-byte field. Cell body follows.

  nk (key node):  signature "nk"
    +0x02 flags (u16)
    +0x04 last-written FILETIME (u64)
    +0x10 parent nk offset (u32, relative to hbin data)
    +0x14 subkey count, stable (u32)
    +0x1c subkey list offset, stable (u32)
    +0x24 value count (u32)
    +0x28 value list offset (u32)
    +0x48 key name length (u16)
    +0x4a class name length (u16)
    +0x4c key name (name-length bytes, ASCII or UTF-8 depending on flags)

  Subkey list, one of:
    "lf"/"lh": u16 count, then count * (u32 offset, u32 hash)
    "li":      u16 count, then count * (u32 offset)
    "ri":      u16 count, then count * (u32 offset to another subkey list)

  vk (value node): signature "vk"
    +0x00 name length (u16)
    +0x02 data length (u32); top bit set => data stored inline in the
          data-offset field itself (only valid when length <= 4)
    +0x06 data offset (u32)
    +0x0a data type (u32)  1=REG_SZ 2=REG_EXPAND_SZ 3=REG_BINARY 4=REG_DWORD
                            7=REG_MULTI_SZ 11=REG_QWORD
    +0x0e flags (u16)      bit0 set => name is ASCII/Latin1, else UTF-16LE
    +0x12 name (name-length bytes)

All offsets stored in cells are relative to the start of the hbin data
region, which begins at absolute file offset 0x1000.
"""


HBIN_START = 0x1000


def filetime_to_datetime(ft: int):
    if ft in (0, None):
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)
    except (OverflowError, OSError):
        return None


class HiveError(Exception):
    pass


class Value:
    __slots__ = ("name", "type", "data")

    TYPE_NAMES = {
        0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
        4: "REG_DWORD", 5: "REG_DWORD_BE", 6: "REG_LINK", 7: "REG_MULTI_SZ",
        11: "REG_QWORD",
    }

    def __init__(self, name, type_, data):
        self.name = name
        self.type = type_
        self.data = data

    def __repr__(self):
        return f"<Value {self.name!r} type={self.TYPE_NAMES.get(self.type, self.type)}>"

    def as_str(self):
        if self.type in (1, 2, 7) and isinstance(self.data, bytes):
            try:
                s = self.data.decode("utf-16-le", errors="ignore")
            except Exception:
                return ""
            return s.rstrip("\x00")
        if self.type == 4 and isinstance(self.data, bytes) and len(self.data) >= 4:
            return str(struct.unpack("<I", self.data[:4])[0])
        if self.type == 11 and isinstance(self.data, bytes) and len(self.data) >= 8:
            return str(struct.unpack("<Q", self.data[:8])[0])
        if isinstance(self.data, bytes):
            return self.data.hex()
        return str(self.data)


class Key:
    def __init__(self, hive, offset):
        self._hive = hive
        self._offset = offset
        cell = hive._cell(offset)
        if cell[0:2] != b"nk":
            raise HiveError(f"expected nk cell at {offset:#x}, got {cell[0:2]!r}")
        self._raw = cell

    @property
    def name(self):
        name_len = struct.unpack_from("<H", self._raw, 0x48)[0]
        flags = struct.unpack_from("<H", self._raw, 0x02)[0]
        raw_name = self._raw[0x4C:0x4C + name_len]
        if flags & 0x20:  # ASCII/Latin1 name
            return raw_name.decode("latin1", errors="replace")
        return raw_name.decode("utf-16-le", errors="replace")

    @property
    def last_write_time(self):
        ft = struct.unpack_from("<Q", self._raw, 0x04)[0]
        return filetime_to_datetime(ft)

    def _subkey_count(self):
        return struct.unpack_from("<I", self._raw, 0x14)[0]

    def _subkey_list_offset(self):
        return struct.unpack_from("<I", self._raw, 0x1C)[0]

    def _value_count(self):
        return struct.unpack_from("<I", self._raw, 0x24)[0]

    def _value_list_offset(self):
        return struct.unpack_from("<I", self._raw, 0x28)[0]

    def subkeys(self):
        count = self._subkey_count()
        list_off = self._subkey_list_offset()
        if count == 0 or list_off in (0xFFFFFFFF, 0):
            return
        for off in self._hive._walk_subkey_list(list_off):
            try:
                yield Key(self._hive, off)
            except HiveError:
                continue

    def subkey(self, name):
        target = name.lower()
        for k in self.subkeys():
            if k.name.lower() == target:
                return k
        return None

    def path(self, *parts):
        """Walk a chain of subkey names, e.g. key.path('Root', 'InventoryApplicationFile')."""
        cur = self
        for p in parts:
            if cur is None:
                return None
            cur = cur.subkey(p)
        return cur

    def values(self):
        count = self._value_count()
        list_off = self._value_list_offset()
        if count == 0 or list_off in (0xFFFFFFFF, 0):
            return
        list_cell = self._hive._cell(list_off)
        # value list is a flat array of u32 offsets, no signature
        for i in range(count):
            pos = i * 4
            if pos + 4 > len(list_cell):
                break
            (voff,) = struct.unpack_from("<I", list_cell, pos)
            v = self._hive._read_vk(voff)
            if v is not None:
                yield v

    def value(self, name):
        target = name.lower()
        for v in self.values():
            if v.name.lower() == target:
                return v
        return None


class Hive:
    def __init__(self, path):
        with open(path, "rb") as f:
            self._data = f.read()
        if self._data[0:4] != b"regf":
            raise HiveError("not a registry hive (missing regf signature)")
        (root_cell_off,) = struct.unpack_from("<I", self._data, 0x24)
        self._root_offset = root_cell_off

    def _cell(self, rel_offset):
        """Return the cell body (after the 4-byte size field) at a hbin-relative offset."""
        abs_off = HBIN_START + rel_offset
        if abs_off < 0 or abs_off + 4 > len(self._data):
            raise HiveError(f"cell offset out of range: {rel_offset:#x}")
        (size,) = struct.unpack_from("<i", self._data, abs_off)
        size = abs(size)
        return self._data[abs_off + 4: abs_off + size]

    def _walk_subkey_list(self, rel_offset):
        cell = self._cell(rel_offset)
        sig = cell[0:2]
        if sig in (b"lf", b"lh"):
            (count,) = struct.unpack_from("<H", cell, 2)
            for i in range(count):
                pos = 4 + i * 8
                if pos + 4 > len(cell):
                    break
                (off,) = struct.unpack_from("<I", cell, pos)
                yield off
        elif sig == b"li":
            (count,) = struct.unpack_from("<H", cell, 2)
            for i in range(count):
                pos = 4 + i * 4
                if pos + 4 > len(cell):
                    break
                (off,) = struct.unpack_from("<I", cell, pos)
                yield off
        elif sig == b"ri":
            (count,) = struct.unpack_from("<H", cell, 2)
            for i in range(count):
                pos = 4 + i * 4
                if pos + 4 > len(cell):
                    break
                (sub_off,) = struct.unpack_from("<I", cell, pos)
                yield from self._walk_subkey_list(sub_off)
        # unknown signature: silently yield nothing rather than raise,
        # so one malformed branch doesn't kill an entire hive walk

    def _read_vk(self, rel_offset):
        try:
            cell = self._cell(rel_offset)
        except HiveError:
            return None
        if cell[0:2] != b"vk":
            return None
        name_len = struct.unpack_from("<H", cell, 0x02)[0]
        data_len_raw = struct.unpack_from("<I", cell, 0x04)[0]
        data_off = struct.unpack_from("<I", cell, 0x08)[0]
        vtype = struct.unpack_from("<I", cell, 0x0C)[0]
        flags = struct.unpack_from("<H", cell, 0x10)[0]
        name_bytes = cell[0x14:0x14 + name_len]
        if name_len == 0:
            name = "(default)"
        elif flags & 0x1:
            name = name_bytes.decode("latin1", errors="replace")
        else:
            name = name_bytes.decode("utf-16-le", errors="replace")

        inline = bool(data_len_raw & 0x80000000)
        data_len = data_len_raw & 0x7FFFFFFF
        if inline:
            data = struct.pack("<I", data_off)[:data_len]
        else:
            try:
                data_cell = self._cell(data_off)
                data = data_cell[:data_len]
            except HiveError:
                data = b""
        return Value(name, vtype, data)

    def root(self):
        return Key(self, self._root_offset)


def open_hive(path):
    return Hive(path)

# ======================================================================
# ---- from parsers/amcache.py ----
# ======================================================================
"""
amcache.py — parses Amcache.hve (C:\\Windows\\AppCompat\\Programs\\Amcache.hve).

Amcache tracks metadata about executables that have been run or present on
the system: path, SHA1, size, publisher, link (compile) timestamp, and the
volume/last-modified time recorded when the entry was created.

Two schema generations exist and both are handled:

  MODERN (Windows 10 1607+): Root\\InventoryApplicationFile\\<GUID-like key>
  Values are named directly (LowerCaseLongPath, FileId, Size, ProductName,
  Publisher, LinkDate, ...) — no ambiguity, high confidence.

  LEGACY (Windows 8 / early Windows 10): Root\\File\\<volume GUID>\\<entry>
  Values are named by a *numeric* ID whose meaning has to be looked up in a
  table. The mapping below is assembled from published DFIR research (Eric
  Zimmerman's AmcacheParser docs and Yogesh Khatri's Amcache research) and
  is the best public reference available, but the exact IDs have shifted
  across Windows builds in the past. Treat legacy-schema output as
  best-effort and cross-check against AmcacheParser.exe on a real hive
  before relying on it for anything load-bearing.

FileId in the modern schema is stored as "0000<sha1>" (a 4-hex-digit flag
prefix followed by the 40-hex-char SHA1) — the prefix is stripped here.
"""


# Legacy numeric value-ID -> field name. BEST EFFORT — see module docstring.
LEGACY_FIELD_MAP = {
    "0": "product_name",
    "1": "company_name",
    "2": "file_version_number",
    "3": "language_code",
    "5": "file_version_string",
    "6": "file_size",
    "8": "file_description",
    "9": "linker_ts",
    "c": "last_modified",
    "f": "program_id",
    "11": "usn",
    "12": "sha1",
    "15": "path",
    "17": "last_modified_2",
}


@dataclass
class AmcacheEntry:
    path: str = ""
    sha1: str = ""
    size: Optional[int] = None
    product_name: str = ""
    publisher: str = ""
    link_date: str = ""
    last_modified: Optional[str] = None
    key_last_write: Optional[str] = None
    schema: str = ""
    raw: dict = field(default_factory=dict)


def _clean_sha1(raw: str) -> str:
    raw = raw.strip().lower()
    if len(raw) == 44 and raw.startswith("0000"):
        return raw[4:]
    return raw


def _parse_modern(inv_key) -> list:
    entries = []
    for entry_key in inv_key.subkeys():
        vals = {v.name: v for v in entry_key.values()}

        def s(name):
            v = vals.get(name)
            return v.as_str() if v else ""

        e = AmcacheEntry(
            path=s("LowerCaseLongPath") or s("Name"),
            sha1=_clean_sha1(s("FileId")),
            product_name=s("ProductName"),
            publisher=s("Publisher"),
            link_date=s("LinkDate"),
            schema="modern (InventoryApplicationFile)",
            raw={k: v.as_str() for k, v in vals.items()},
        )
        size_s = s("Size")
        if size_s.isdigit():
            e.size = int(size_s)
        klw = entry_key.last_write_time
        e.key_last_write = klw.isoformat() if klw else None
        entries.append(e)
    return entries


def _parse_legacy(file_key) -> list:
    entries = []
    for vol_key in file_key.subkeys():          # per-volume GUID keys
        for entry_key in vol_key.subkeys():      # one per executable
            fields = {}
            for v in entry_key.values():
                mapped = LEGACY_FIELD_MAP.get(v.name.lower())
                if mapped:
                    fields[mapped] = v.as_str()
                else:
                    fields[f"raw_{v.name}"] = v.as_str()
            e = AmcacheEntry(
                path=fields.get("path", ""),
                sha1=_clean_sha1(fields.get("sha1", "")),
                product_name=fields.get("product_name", ""),
                schema="legacy (File\\<volume>)",
                raw=fields,
            )
            size = fields.get("file_size")
            if size and size.isdigit():
                e.size = int(size)
            klw = entry_key.last_write_time
            e.key_last_write = klw.isoformat() if klw else None
            entries.append(e)
    return entries


def parse_amcache(path: str):
    """Returns a list of AmcacheEntry. Tries the modern schema first, then legacy."""
    hive = open_hive(path)
    root = hive.root()

    entries = []
    inv = root.path("Root", "InventoryApplicationFile")
    if inv is not None:
        entries.extend(_parse_modern(inv))

    file_key = root.path("Root", "File")
    if file_key is not None:
        entries.extend(_parse_legacy(file_key))

    return entries

# ======================================================================
# ---- from parsers/bam.py ----
# ======================================================================
"""
bam.py — parses execution history from the Background Activity Moderator
(BAM) key inside the SYSTEM registry hive.

Location (schema has been stable since Windows 10 1709):
  ControlSet00X\\Services\\bam\\State\\UserSettings\\<user SID>\\

Each value under a SID subkey is named with the *full path* of an
executable; the value data is REG_BINARY whose first 8 bytes are a
FILETIME recording when that executable was last run. Some builds append
extra flag bytes after the FILETIME — those are read but not decoded here,
since their meaning isn't consistently documented across versions.

Which ControlSet is "active" is normally given by SYSTEM\\Select\\Current,
but a live/offline SYSTEM hive may contain several ControlSet00X keys
(ControlSet001, ControlSet002, ...). This module checks Select\\Current
when present and otherwise scans every ControlSet00X it finds, so nothing
is silently missed.
"""



@dataclass
class BamEntry:
    sid: str
    path: str
    last_run: Optional[str]
    control_set: str


def _current_control_set_name(root) -> Optional[str]:
    select = root.subkey("Select")
    if select is None:
        return None
    v = select.value("Current")
    if v is None:
        return None
    try:
        n = int(v.as_str())
    except ValueError:
        return None
    return f"ControlSet{n:03d}"


def _control_set_names(root) -> List[str]:
    names = []
    preferred = _current_control_set_name(root)
    if preferred and root.subkey(preferred):
        names.append(preferred)
    for k in root.subkeys():
        if k.name.lower().startswith("controlset") and k.name not in names:
            names.append(k.name)
    return names


def parse_bam(system_hive_path: str) -> List[BamEntry]:
    hive = open_hive(system_hive_path)
    root = hive.root()

    entries: List[BamEntry] = []
    for cs_name in _control_set_names(root):
        bam_root = root.path(cs_name, "Services", "bam", "State", "UserSettings")
        if bam_root is None:
            # Some builds nest under "bam", not "bam\State" — try that too.
            bam_root = root.path(cs_name, "Services", "bam", "UserSettings")
        if bam_root is None:
            continue
        for sid_key in bam_root.subkeys():
            for v in sid_key.values():
                if v.name == "(default)" or not isinstance(v.data, (bytes, bytearray)):
                    continue
                if len(v.data) < 8:
                    continue
                (filetime,) = struct.unpack_from("<Q", v.data, 0)
                dt = filetime_to_datetime(filetime)
                entries.append(BamEntry(
                    sid=sid_key.name,
                    path=v.name,
                    last_run=dt.isoformat() if dt else None,
                    control_set=cs_name,
                ))
    return entries

# ======================================================================
# ---- from parsers/prefetch.py ----
# ======================================================================
"""
prefetch.py — parses Windows Prefetch (.pf) files from
C:\\Windows\\Prefetch\\.

CONFIDENCE NOTES (read before trusting output):

  - Executable name, prefetch hash, and the "files referenced during
    execution" list (section C) are parsed from header fields that are
    stable across prefetch format versions 17/23/26/30/31. These are the
    values I'm confident in.

  - Last-run timestamp(s) and run count live at offsets that DO shift
    between format versions, and I do not have a way to test this parser
    against real .pf files in this environment. The offsets below are my
    best recollection of the documented layout, gated by version, but
    you should validate them against a trusted reference tool (e.g.
    Eric Zimmerman's PECmd, or WinPrefetchView) on a handful of real
    files before relying on the run-time/run-count fields for anything
    that matters. The GUI surfaces this as a warning for the same reason.

  - Windows 10/11 prefetch files are usually MAM-compressed (they start
    with the 4 bytes "MAM\\x04"). Decompressing that requires the real
    Windows LZ77+Huffman implementation. Rather than reimplement that
    format by hand (high risk of subtle bugs), this module calls the
    OS's own decompressor via ctypes (ntdll!RtlDecompressBuffer), which
    only works when actually running on Windows. On non-Windows systems,
    compressed .pf files can't be read here — decompress them first with
    a tool that has access to that API, or run this on Windows.
"""


COMPRESSION_FORMAT_XPRESS_HUFF = 4


class PrefetchError(Exception):
    pass


@dataclass
class PrefetchInfo:
    version: int
    executable_name: str
    prefetch_hash: str
    file_size: Optional[int]
    run_count: Optional[int]
    last_run_times: List[str] = field(default_factory=list)
    referenced_files: List[str] = field(default_factory=list)
    volume_count: Optional[int] = None
    timestamps_confidence: str = "unverified"


def _decompress_mam(data: bytes) -> bytes:
    if os.name != "nt":
        raise PrefetchError(
            "This .pf file is MAM-compressed (Windows 10/11 style). "
            "Decompressing it requires the Windows decompression API, "
            "so this needs to run on a Windows machine — decompress it "
            "there, or run deepchecks itself on Windows."
        )
    decompressed_size = struct.unpack_from("<I", data, 4)[0]
    compressed = data[8:]

    ntdll = ctypes.WinDLL("ntdll")
    out_buf = ctypes.create_string_buffer(decompressed_size)
    final_size = ctypes.c_ulong(0)

    status = ntdll.RtlDecompressBuffer(
        ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
        out_buf,
        ctypes.c_ulong(decompressed_size),
        compressed,
        ctypes.c_ulong(len(compressed)),
        ctypes.byref(final_size),
    )
    if status != 0:
        raise PrefetchError(f"RtlDecompressBuffer failed, NTSTATUS={status:#x}")
    return out_buf.raw[: final_size.value]


def _filetime_to_iso(ft: int) -> Optional[str]:
    dt = filetime_to_datetime(ft)
    return dt.isoformat() if dt else None


def parse_prefetch(path: str) -> PrefetchInfo:
    with open(path, "rb") as f:
        data = f.read()

    if data[0:4] == b"MAM\x04":
        data = _decompress_mam(data)

    if data[4:8] != b"SCCA":
        raise PrefetchError("missing SCCA signature — not a prefetch file (or still compressed)")

    version = struct.unpack_from("<I", data, 0)[0]
    exe_name_raw = data[0x10:0x10 + 60]
    executable_name = exe_name_raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
    prefetch_hash = f"{struct.unpack_from('<I', data, 0x4C)[0]:08X}"

    # Section C: filenames referenced during execution (DLLs etc.)
    sec_c_off, sec_c_len = struct.unpack_from("<II", data, 0x64)
    referenced_files = []
    if 0 < sec_c_off < len(data):
        blob = data[sec_c_off:sec_c_off + sec_c_len]
        # Split on a *2-byte-aligned* null pair — plain bytes.split(b"\x00\x00")
        # is wrong here because a null byte pair can appear misaligned across
        # two adjacent UTF-16LE code units and corrupt everything after it.
        current = bytearray()
        for i in range(0, len(blob) - 1, 2):
            unit = blob[i:i + 2]
            if unit == b"\x00\x00":
                if current:
                    s = bytes(current).decode("utf-16-le", errors="ignore")
                    if s:
                        referenced_files.append(s)
                    current = bytearray()
            else:
                current += unit
        if current:
            s = bytes(current).decode("utf-16-le", errors="ignore")
            if s:
                referenced_files.append(s)

    volume_count = None
    try:
        volume_count = struct.unpack_from("<I", data, 0x70)[0]
    except struct.error:
        pass

    # --- run count / last-run times: version-gated, UNVERIFIED offsets ---
    run_count = None
    last_run_times = []
    try:
        if version == 17:  # XP
            (ft,) = struct.unpack_from("<Q", data, 0x78)
            iso = _filetime_to_iso(ft)
            if iso:
                last_run_times.append(iso)
            run_count = struct.unpack_from("<I", data, 0x90)[0]
        elif version == 23:  # Vista/7
            (ft,) = struct.unpack_from("<Q", data, 0x80)
            iso = _filetime_to_iso(ft)
            if iso:
                last_run_times.append(iso)
            run_count = struct.unpack_from("<I", data, 0x98)[0]
        elif version in (26, 30, 31):  # 8/8.1/10/11 — up to 8 stored run times
            for i in range(8):
                off = 0x80 + i * 8
                if off + 8 > len(data):
                    break
                (ft,) = struct.unpack_from("<Q", data, off)
                iso = _filetime_to_iso(ft)
                if iso:
                    last_run_times.append(iso)
            rc_off = 0xD0 if version in (30, 31) else 0xC8
            if rc_off + 4 <= len(data):
                run_count = struct.unpack_from("<I", data, rc_off)[0]
    except struct.error:
        pass

    return PrefetchInfo(
        version=version,
        executable_name=executable_name,
        prefetch_hash=prefetch_hash,
        file_size=struct.unpack_from("<I", data, 0x0C)[0] if len(data) >= 0x10 else None,
        run_count=run_count,
        last_run_times=last_run_times,
        referenced_files=referenced_files,
        volume_count=volume_count,
        timestamps_confidence="unverified — validate against PECmd/WinPrefetchView",
    )

# ======================================================================
# ---- from parsers/mft.py ----
# ======================================================================
"""
mft.py — parses an extracted NTFS $MFT file into per-record metadata:
filename(s), parent directory reference, in-use/directory flags, and the
STANDARD_INFORMATION / FILE_NAME timestamp sets.

This does NOT read a live volume's $MFT itself — grabbing $MFT off a
mounted, in-use volume needs raw-volume access (SeBackupPrivilege + an API
like FSCTL_GET_NTFS_VOLUME_DATA, or a tool like FTK Imager / RawCopy / KAPE
to export it first). Point this parser at an already-extracted $MFT file.

Record layout, fixup handling, and attribute offsets below follow the
publicly documented NTFS on-disk structure (the same structure described
independently by libfsntfs, analyzeMFT, and Microsoft's own old NTFS.SYS
symbol dumps). Standard caveats:

  - Assumes 512-byte sectors (default 1024-byte records) for fixup
    application. This is by far the most common configuration; pass
    record_size= if a volume was formatted with a non-default cluster/
    record size.
  - $MFT record 5 is the root directory; well-known low record numbers
    (0-15) are NTFS metadata files ($MFT, $MFTMirr, $LogFile, $Volume,
    $AttrDef, root, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend),
    which is worth knowing when triaging output.
  - Only resident FILE_NAME/STANDARD_INFORMATION attributes are parsed
    (these are always resident by spec, so this isn't a limitation for
    those two). DATA attribute parsing only reports size fields, not
    data runs / actual content.
"""


RECORD_SIG_OK = b"FILE"
RECORD_SIG_BAD = b"BAAD"

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF

NAMESPACE = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32_DOS"}


@dataclass
class FileNameAttr:
    parent_record: int
    parent_seq: int
    namespace: str
    name: str
    allocated_size: int
    real_size: int
    created: Optional[str]
    modified: Optional[str]
    mft_modified: Optional[str]
    accessed: Optional[str]


@dataclass
class MFTRecord:
    record_number: int
    in_use: bool
    is_directory: bool
    sequence_number: int
    hard_link_count: int
    base_record: int
    si_created: Optional[str] = None
    si_modified: Optional[str] = None
    si_mft_modified: Optional[str] = None
    si_accessed: Optional[str] = None
    si_file_attributes: Optional[int] = None
    file_names: List[FileNameAttr] = field(default_factory=list)
    data_real_size: Optional[int] = None
    damaged: bool = False

    @property
    def best_name(self) -> str:
        if not self.file_names:
            return ""
        # prefer a Win32 (or Win32&DOS) name over a bare DOS 8.3 name
        for fn in self.file_names:
            if fn.namespace in ("WIN32", "WIN32_DOS", "POSIX"):
                return fn.name
        return self.file_names[0].name


def _apply_fixup(record: bytearray, bytes_per_sector: int = 512) -> bool:
    """Applies the update-sequence-array fixup in place. Returns False if the
    embedded USN check fails (record likely corrupt / partially overwritten)."""
    if len(record) < 8:
        return False
    usa_offset, usa_size = struct.unpack_from("<HH", record, 0x04)
    if usa_size == 0 or usa_offset + usa_size * 2 > len(record):
        return False
    usn = record[usa_offset:usa_offset + 2]
    ok = True
    for i in range(usa_size - 1):
        sector_end = (i + 1) * bytes_per_sector
        check_pos = sector_end - 2
        if check_pos + 2 > len(record):
            break
        if bytes(record[check_pos:check_pos + 2]) != bytes(usn):
            ok = False
        replacement = record[usa_offset + 2 + i * 2: usa_offset + 4 + i * 2]
        record[check_pos:check_pos + 2] = replacement
    return ok


def _ft(record, offset) -> Optional[str]:
    (val,) = struct.unpack_from("<Q", record, offset)
    dt = filetime_to_datetime(val)
    return dt.isoformat() if dt else None


def _parse_record(raw: bytes, record_number: int) -> Optional[MFTRecord]:
    buf = bytearray(raw)
    if buf[0:4] == RECORD_SIG_BAD:
        return MFTRecord(record_number, False, False, 0, 0, 0, damaged=True)
    if buf[0:4] != RECORD_SIG_OK:
        return None  # unused / uninitialized slot

    fixup_ok = _apply_fixup(buf)

    seq_number, hard_links = struct.unpack_from("<HH", buf, 0x10)
    first_attr_off = struct.unpack_from("<H", buf, 0x14)[0]
    flags = struct.unpack_from("<H", buf, 0x16)[0]
    base_ref = struct.unpack_from("<Q", buf, 0x20)[0]
    base_record = base_ref & 0xFFFFFFFFFFFF

    rec = MFTRecord(
        record_number=record_number,
        in_use=bool(flags & 0x01),
        is_directory=bool(flags & 0x02),
        sequence_number=seq_number,
        hard_link_count=hard_links,
        base_record=base_record,
        damaged=not fixup_ok,
    )

    pos = first_attr_off
    while pos + 8 <= len(buf):
        attr_type = struct.unpack_from("<I", buf, pos)[0]
        if attr_type == ATTR_END or attr_type == 0:
            break
        attr_len = struct.unpack_from("<I", buf, pos + 4)[0]
        if attr_len == 0 or pos + attr_len > len(buf):
            break
        non_resident = buf[pos + 8]

        if attr_type == ATTR_STANDARD_INFORMATION and not non_resident:
            content_len, content_off = struct.unpack_from("<IH", buf, pos + 0x10)
            c = pos + content_off
            if c + 0x24 <= len(buf):
                rec.si_created = _ft(buf, c + 0x00)
                rec.si_modified = _ft(buf, c + 0x08)
                rec.si_mft_modified = _ft(buf, c + 0x10)
                rec.si_accessed = _ft(buf, c + 0x18)
                rec.si_file_attributes = struct.unpack_from("<I", buf, c + 0x20)[0]

        elif attr_type == ATTR_FILE_NAME and not non_resident:
            content_len, content_off = struct.unpack_from("<IH", buf, pos + 0x10)
            c = pos + content_off
            if c + 0x42 <= len(buf):
                parent_ref = struct.unpack_from("<Q", buf, c + 0x00)[0]
                name_len_chars = buf[c + 0x40]
                namespace_id = buf[c + 0x41]
                name_bytes = bytes(buf[c + 0x42: c + 0x42 + name_len_chars * 2])
                try:
                    name = name_bytes.decode("utf-16-le", errors="replace")
                except Exception:
                    name = ""
                rec.file_names.append(FileNameAttr(
                    parent_record=parent_ref & 0xFFFFFFFFFFFF,
                    parent_seq=(parent_ref >> 48) & 0xFFFF,
                    namespace=NAMESPACE.get(namespace_id, str(namespace_id)),
                    name=name,
                    allocated_size=struct.unpack_from("<Q", buf, c + 0x28)[0],
                    real_size=struct.unpack_from("<Q", buf, c + 0x30)[0],
                    created=_ft(buf, c + 0x08),
                    modified=_ft(buf, c + 0x10),
                    mft_modified=_ft(buf, c + 0x18),
                    accessed=_ft(buf, c + 0x20),
                ))

        elif attr_type == ATTR_DATA:
            if non_resident:
                if pos + 0x38 <= len(buf):
                    rec.data_real_size = struct.unpack_from("<Q", buf, pos + 0x30)[0]
            else:
                content_len = struct.unpack_from("<I", buf, pos + 0x10)[0]
                rec.data_real_size = content_len

        pos += attr_len

    return rec


def parse_mft(path: str, record_size: int = 1024):
    """Generator yielding MFTRecord for every in-range record in the file."""
    with open(path, "rb") as f:
        idx = 0
        while True:
            raw = f.read(record_size)
            if len(raw) < record_size:
                break
            rec = _parse_record(raw, idx)
            if rec is not None:
                yield rec
            idx += 1

# ======================================================================
# ---- from parsers/browsing_history.py ----
# ======================================================================
"""
browsing_history.py — consolidates browsing history from Chromium-family
browsers (Chrome, Edge, Brave, Opera — all share the same SQLite schema)
and Firefox into one unified list.

Chromium "History" file (SQLite):
  urls(id, url, title, visit_count, ...)
  visits(id, url [FK -> urls.id], visit_time, ...)

Firefox "places.sqlite":
  moz_places(id, url, title, visit_count, ...)
  moz_historyvisits(id, place_id [FK -> moz_places.id], visit_date, ...)

Both are well-documented, stable schemas (they've barely changed in
years), so this is on solid ground — verified here against hand-built
synthetic databases created with the stdlib sqlite3 module
(test_browsing_history_synthetic.py), not just read from memory of the
schema.

Browsers hold their history DB open (sometimes with -wal/-shm sidecar
files) while running, which can cause "database is locked" errors on a
live system. This module copies the DB (and any sidecars) to a temp
directory before opening it, the same workaround every browser-history
forensic tool uses.
"""




@dataclass
class HistoryEntry:
    browser: str
    url: str
    title: str
    visit_time: Optional[str]
    visit_count: Optional[int]


def _copy_with_sidecars(path: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="deepchecks_")
    dest = os.path.join(tmpdir, os.path.basename(path))
    shutil.copy2(path, dest)
    for ext in ("-wal", "-shm", "-journal"):
        side = path + ext
        if os.path.exists(side):
            shutil.copy2(side, dest + ext)
    return dest


def _table_exists(cur, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def _looks_like_chromium(cur) -> bool:
    return _table_exists(cur, "urls") and _table_exists(cur, "visits")


def _looks_like_firefox(cur) -> bool:
    return _table_exists(cur, "moz_places") and _table_exists(cur, "moz_historyvisits")


def _parse_chromium(cur, browser_label: str) -> List[HistoryEntry]:
    entries = []
    cur.execute("""
        SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
        FROM visits JOIN urls ON visits.url = urls.id
        ORDER BY visits.visit_time DESC
    """)
    for url, title, visit_count, visit_time in cur.fetchall():
        dt = chrome_time_to_datetime(visit_time)
        entries.append(HistoryEntry(
            browser=browser_label, url=url or "", title=title or "",
            visit_time=dt.isoformat() if dt else None, visit_count=visit_count,
        ))
    return entries


def _parse_firefox(cur) -> List[HistoryEntry]:
    entries = []
    cur.execute("""
        SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_historyvisits.visit_date
        FROM moz_historyvisits JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
        ORDER BY moz_historyvisits.visit_date DESC
    """)
    for url, title, visit_count, visit_date in cur.fetchall():
        dt = firefox_time_to_datetime(visit_date)
        entries.append(HistoryEntry(
            browser="Firefox", url=url or "", title=title or "",
            visit_time=dt.isoformat() if dt else None, visit_count=visit_count,
        ))
    return entries


def parse_browsing_history(path: str, browser_label: str = "Chromium") -> List[HistoryEntry]:
    """Auto-detects Chromium-family vs Firefox schema from the file itself."""
    local_copy = _copy_with_sidecars(path)
    try:
        conn = sqlite3.connect(f"file:{local_copy}?mode=ro", uri=True)
        cur = conn.cursor()
        if _looks_like_chromium(cur):
            return _parse_chromium(cur, browser_label)
        if _looks_like_firefox(cur):
            return _parse_firefox(cur)
        raise ValueError("doesn't look like a Chromium 'History' file or a Firefox 'places.sqlite'")
    finally:
        conn.close()
        shutil.rmtree(os.path.dirname(local_copy), ignore_errors=True)

# ======================================================================
# ---- from parsers/downloads_history.py ----
# ======================================================================
"""
downloads_history.py — consolidates download history from Chromium-family
browsers and Firefox.

Chromium "History" file, table `downloads` (+ `downloads_url_chains` on
older schemas where the source URL isn't inlined). Column names have
shifted a bit across Chrome versions (`current_path` -> `target_path`,
a standalone `url` column -> `tab_url` + `downloads_url_chains`), so this
checks `PRAGMA table_info(downloads)` first and adapts rather than
assuming one fixed schema. HIGH confidence on a modern (current_path/
target_path + tab_url) schema; older Chrome versions may need the
fallback path exercised more than it's been tested here.

Firefox stopped keeping a dedicated downloads table around Firefox 26;
since then download records live as annotations on the destination
`moz_places` entry (anno_attribute 'downloads/destinationFileURI'). This
path is LOWER confidence — it's a reasonable reading of how Firefox
does it, but annotations are a more obscure corner of places.sqlite than
plain history, so validate it against a real profile before trusting it.
"""




@dataclass
class DownloadEntry:
    browser: str
    path: str
    source_url: str
    start_time: Optional[str]
    end_time: Optional[str]
    received_bytes: Optional[int]
    total_bytes: Optional[int]
    state: str
    confidence: str = "high"


def _copy_with_sidecars(path: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="deepchecks_")
    dest = os.path.join(tmpdir, os.path.basename(path))
    shutil.copy2(path, dest)
    for ext in ("-wal", "-shm", "-journal"):
        side = path + ext
        if os.path.exists(side):
            shutil.copy2(side, dest + ext)
    return dest


def _table_exists(cur, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def _columns(cur, table: str) -> set:
    cur.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}

# Chromium's `state` column is an integer enum; this mapping matches the
# values that have been stable since the downloads table was introduced.
_CHROME_STATE = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}


def _parse_chromium_downloads(cur) -> List[DownloadEntry]:
    cols = _columns(cur, "downloads")
    path_col = "target_path" if "target_path" in cols else ("current_path" if "current_path" in cols else None)
    url_col = "tab_url" if "tab_url" in cols else ("url" if "url" in cols else None)
    if path_col is None:
        raise ValueError("downloads table has neither target_path nor current_path — unrecognized schema")

    id_col = "id" if "id" in cols else None
    select_cols = [path_col, "start_time", "end_time", "received_bytes", "total_bytes", "state"]
    if url_col:
        select_cols.append(url_col)
    if id_col:
        select_cols.append(id_col)
    cur.execute(f"SELECT {', '.join(select_cols)} FROM downloads")
    rows = cur.fetchall()

    # Fallback source URL from downloads_url_chains when there's no inline url column
    chain_urls = {}
    if url_col is None and id_col and _table_exists(cur, "downloads_url_chains"):
        cur.execute("SELECT id, url FROM downloads_url_chains WHERE chain_index = 0")
        chain_urls = dict(cur.fetchall())

    entries = []
    for row in rows:
        row = dict(zip(select_cols, row))
        start_dt = chrome_time_to_datetime(row.get("start_time"))
        end_dt = chrome_time_to_datetime(row.get("end_time"))
        source_url = row.get(url_col, "") if url_col else chain_urls.get(row.get(id_col), "")
        entries.append(DownloadEntry(
            browser="Chromium",
            path=row.get(path_col) or "",
            source_url=source_url or "",
            start_time=start_dt.isoformat() if start_dt else None,
            end_time=end_dt.isoformat() if end_dt else None,
            received_bytes=row.get("received_bytes"),
            total_bytes=row.get("total_bytes"),
            state=_CHROME_STATE.get(row.get("state"), str(row.get("state"))),
            confidence="high",
        ))
    return entries


def _parse_firefox_downloads(cur) -> List[DownloadEntry]:
    if not _table_exists(cur, "moz_annos") or not _table_exists(cur, "moz_anno_attributes"):
        return []
    cur.execute("""
        SELECT moz_places.url, moz_annos.content, moz_annos.dateAdded
        FROM moz_annos
        JOIN moz_anno_attributes ON moz_annos.anno_attribute_id = moz_anno_attributes.id
        JOIN moz_places ON moz_annos.place_id = moz_places.id
        WHERE moz_anno_attributes.name = 'downloads/destinationFileURI'
    """)
    entries = []
    for source_url, dest_uri, date_added in cur.fetchall():
        dt = firefox_time_to_datetime(date_added)
        local_path = unquote(urlparse(dest_uri or "").path) if dest_uri else ""
        entries.append(DownloadEntry(
            browser="Firefox",
            path=local_path,
            source_url=source_url or "",
            start_time=dt.isoformat() if dt else None,
            end_time=None,
            received_bytes=None,
            total_bytes=None,
            state="unknown",
            confidence="lower — Firefox annotation-based, validate against a real profile",
        ))
    return entries


def parse_downloads_history(path: str) -> List[DownloadEntry]:
    local_copy = _copy_with_sidecars(path)
    try:
        conn = sqlite3.connect(f"file:{local_copy}?mode=ro", uri=True)
        cur = conn.cursor()
        if _table_exists(cur, "downloads"):
            return _parse_chromium_downloads(cur)
        if _table_exists(cur, "moz_places"):
            return _parse_firefox_downloads(cur)
        raise ValueError("doesn't look like a Chromium 'History' file or a Firefox 'places.sqlite'")
    finally:
        conn.close()
        shutil.rmtree(os.path.dirname(local_copy), ignore_errors=True)

# ======================================================================
# ---- from parsers/usb.py ----
# ======================================================================
"""
usb.py — parses USB storage device history from the SYSTEM registry hive.

Location:
  ControlSet00X\\Enum\\USBSTOR\\<DeviceType>\\<InstanceID>   (mass storage)
  ControlSet00X\\Enum\\USB\\<VID_xxxx&PID_xxxx>\\<Serial>     (all USB devices)

Each device instance key holds FriendlyName/DeviceDesc/Mfg values. There's
no dedicated "last connected" timestamp field at this level — the
standard low-effort proxy every free USB-history tool uses is the
registry key's own last-write time, which is updated whenever Windows
touches the device's enumeration entry (typically on connect). This is
useful and commonly cited, but it's an approximation, not a certified
"last plugged in" timestamp — flagged as such in the output.

(A more precise last-connect time exists in the newer per-property
"Device Properties" store, e.g. under the key's Properties subkey /
{83da6326-97a6-4088-9453-a1923f573b29} GUID — that's a more obscure,
higher-effort structure and isn't parsed here.)
"""



@dataclass
class UsbEntry:
    enum_path: str          # "USBSTOR" or "USB"
    device_type: str        # e.g. "Disk&Ven_..." or "VID_xxxx&PID_xxxx"
    instance_id: str        # serial number / instance
    friendly_name: str
    device_desc: str
    mfg: str
    last_key_write: Optional[str]
    confidence: str = "key last-write time is a proxy for last-connected, not exact"


def _control_set_names(root) -> List[str]:
    names = []
    select = root.subkey("Select")
    if select is not None:
        v = select.value("Current")
        if v is not None:
            try:
                n = int(v.as_str())
                preferred = f"ControlSet{n:03d}"
                if root.subkey(preferred):
                    names.append(preferred)
            except ValueError:
                pass
    for k in root.subkeys():
        if k.name.lower().startswith("controlset") and k.name not in names:
            names.append(k.name)
    return names


def _val(key, name) -> str:
    v = key.value(name)
    return v.as_str() if v else ""


def _walk_enum_branch(enum_root, branch_name) -> List[UsbEntry]:
    entries = []
    branch = enum_root.subkey(branch_name)
    if branch is None:
        return entries
    for device_type_key in branch.subkeys():
        for instance_key in device_type_key.subkeys():
            klw = instance_key.last_write_time
            entries.append(UsbEntry(
                enum_path=branch_name,
                device_type=device_type_key.name,
                instance_id=instance_key.name,
                friendly_name=_val(instance_key, "FriendlyName"),
                device_desc=_val(instance_key, "DeviceDesc"),
                mfg=_val(instance_key, "Mfg"),
                last_key_write=klw.isoformat() if klw else None,
            ))
    return entries


def parse_usb(system_hive_path: str) -> List[UsbEntry]:
    hive = open_hive(system_hive_path)
    root = hive.root()

    entries: List[UsbEntry] = []
    for cs_name in _control_set_names(root):
        enum_root = root.path(cs_name, "Enum")
        if enum_root is None:
            continue
        entries.extend(_walk_enum_branch(enum_root, "USBSTOR"))
        entries.extend(_walk_enum_branch(enum_root, "USB"))
    return entries

# ======================================================================
# ---- from parsers/psreadline.py ----
# ======================================================================
"""
psreadline.py — reads PowerShell command history from PSReadLine's history
file:

  %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
  (PowerShell 7: %APPDATA%\\Microsoft\\PowerShell\\PSReadLine\\ConsoleHost_history.txt)

This is a plain UTF-8 text file, one command per line (PSReadLine escapes
literal newlines within a single command as a backtick + newline, which
this parser un-escapes back into one logical command). HIGH confidence —
it's just a text file, no binary format to get wrong.

IMPORTANT LIMITATION: this file does NOT contain timestamps or exit
codes — PSReadLine only stores the command text itself. If you need
*when* a command ran, that requires the "PowerShell Operational" or
"Windows PowerShell" Event Log (specifically Event ID 4104 for script
block logging, if enabled) — parsing .evtx event logs is a separate,
more complex binary format that isn't implemented here.
"""



@dataclass
class HistoryLine:
    line_number: int
    command: str


def parse_psreadline_history(path: str) -> List[HistoryLine]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # PSReadLine escapes an embedded newline within one logical command as
    # "`\n" (backtick then newline). Rejoin those before splitting into
    # separate history entries.
    raw = raw.replace("`\r\n", "\x00").replace("`\n", "\x00")
    lines = raw.splitlines()

    entries = []
    for i, line in enumerate(lines, start=1):
        command = line.replace("\x00", "\n").strip()
        if command:
            entries.append(HistoryLine(line_number=i, command=command))
    return entries

# ======================================================================
# ---- from parsers/pe_strings.py ----
# ======================================================================
"""
pe_strings.py — StringExplorer++: extracts printable strings from any file,
and additionally reads PE (EXE/DLL) header fields when the file is one:
compile timestamp (COFF header TimeDateStamp) and per-file Shannon entropy.
Optional VirusTotal hash lookup if you supply your own API key.

PE header fields read here (DOS header e_lfanew -> COFF file header) are a
small, stable, well-documented part of the PE format (Microsoft's own PE/COFF
spec) — HIGH confidence, verified against a hand-built synthetic PE-ish
header in this build (test_pe_strings_synthetic.py). This does NOT parse
imports, exports, or sections in detail — it's deliberately scoped to the
handful of fields StringExplorer's description called for (compile date,
entropy, strings), not a full PE-file explorer.

VirusTotal integration requires the file's SHA256 and your own VT API key
(get one free at virustotal.com) — this tool never bundles or assumes a
key. Without a key, VT lookup is simply skipped.
"""



@dataclass
class PEInfo:
    is_pe: bool
    compile_time: Optional[str] = None
    machine: Optional[str] = None
    number_of_sections: Optional[int] = None


@dataclass
class FileAnalysis:
    path: str
    size: int
    sha256: str
    entropy: float
    pe: PEInfo
    ascii_strings: List[str] = field(default_factory=list)
    wide_strings: List[str] = field(default_factory=list)
    vt_positives: Optional[str] = None
    vt_total: Optional[str] = None
    vt_error: Optional[str] = None

_MACHINE_TYPES = {
    0x014c: "x86", 0x8664: "x64", 0x01c0: "ARM", 0xaa64: "ARM64", 0x0200: "IA64",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def parse_pe_header(data: bytes) -> PEInfo:
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return PEInfo(is_pe=False)
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return PEInfo(is_pe=False)
    coff_start = e_lfanew + 4
    machine, num_sections, timestamp = struct.unpack_from("<HHI", data, coff_start)
    dt = None
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        dt = None
    return PEInfo(
        is_pe=True,
        compile_time=dt.isoformat() if dt else None,
        machine=_MACHINE_TYPES.get(machine, f"0x{machine:04x}"),
        number_of_sections=num_sections,
    )


_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_ascii_strings(data: bytes, max_count=5000) -> List[str]:
    out = []
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("ascii"))
        if len(out) >= max_count:
            break
    return out


def extract_wide_strings(data: bytes, max_count=5000) -> List[str]:
    # UTF-16LE printable runs: ASCII byte, 0x00, ASCII byte, 0x00, ... (4+ chars)
    #
    # KNOWN LIMITATION: this is a byte-pattern heuristic, not a real UTF-16
    # decoder with known alignment — every naive wide-string scanner has
    # this same limitation. When a null-terminated ASCII string sits
    # immediately before a real UTF-16LE string, the ASCII string's last
    # character plus its own null terminator can look like the start of a
    # UTF-16 code unit, producing a one-character-early match (e.g. an
    # extra leading letter tacked onto the real wide string). This is the
    # same trade-off tools like classic `strings -e l` make; there's no
    # fully general fix without a real UTF-16 boundary source.
    out = []
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    for m in pattern.finditer(data):
        try:
            out.append(m.group().decode("utf-16-le"))
        except UnicodeDecodeError:
            continue
        if len(out) >= max_count:
            break
    return out


def vt_lookup(sha256: str, api_key: str, timeout=10):
    """Returns (positives_str, total_str) or raises on error. Requires network
    and your own VirusTotal API key — never bundled, always opt-in."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    return str(malicious), str(total)


def analyze_file(path: str, vt_api_key: Optional[str] = None) -> FileAnalysis:
    with open(path, "rb") as f:
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()
    fa = FileAnalysis(
        path=path,
        size=len(data),
        sha256=sha256,
        entropy=round(shannon_entropy(data), 4),
        pe=parse_pe_header(data),
        ascii_strings=extract_ascii_strings(data),
        wide_strings=extract_wide_strings(data),
    )
    if vt_api_key:
        try:
            positives, total = vt_lookup(sha256, vt_api_key)
            fa.vt_positives, fa.vt_total = positives, total
        except urllib.error.HTTPError as e:
            fa.vt_error = f"HTTP {e.code}"
        except Exception as e:
            fa.vt_error = str(e)
    return fa

# ======================================================================
# ---- from parsers/lnk.py ----
# ======================================================================
"""
lnk.py — SavedFilesViewer++: parses Windows .lnk shortcut files, most
usefully the ones Windows auto-creates in
%AppData%\\Microsoft\\Windows\\Recent\\ every time a file is opened. Each
one records the target file's path plus its creation/access/write
timestamps *as they were at the moment the shortcut was made* — which is
exactly the kind of "file was saved / opened, and when" trail the original
SavedFilesViewer++ description was going for. Entirely local: this reads
files already on disk, no browser or network involved.

Format reference: MS-SHLLINK (Microsoft's own published Shell Link Binary
File Format spec). This parses the fixed 76-byte header (always present,
HIGH confidence) and the LinkInfo structure's LocalBasePath (present for
shortcuts pointing at local files, HIGH confidence for that common case).
It does NOT parse the LinkTargetIDList shell item structures in detail,
network-path shortcuts (CommonNetworkRelativeLink), or extra data blocks
(environment variables, tracker data) — those are real .lnk sub-formats
this build doesn't attempt, so a shortcut to a network share or one
relying solely on the IDList for its path may come back with an empty
target_path here even though the file parses without error.
"""


HEADER_SIZE = 0x4C

HAS_LINK_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002


@dataclass
class LnkInfo:
    target_path: str
    target_size: Optional[int]
    target_created: Optional[str]
    target_accessed: Optional[str]
    target_modified: Optional[str]
    show_command: int


def _read_cstr_at(data: bytes, offset: int, unicode: bool) -> str:
    if offset == 0 or offset >= len(data):
        return ""
    if unicode:
        end = data.find(b"\x00\x00", offset)
        if end != -1 and (end - offset) % 2 != 0:
            end += 1
        chunk = data[offset:end if end != -1 else len(data)]
        return chunk.decode("utf-16-le", errors="ignore")
    else:
        end = data.find(b"\x00", offset)
        chunk = data[offset:end if end != -1 else len(data)]
        return chunk.decode("latin1", errors="ignore")


def parse_lnk(path: str) -> LnkInfo:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE:
        raise ValueError("file too short to be a .lnk")
    (header_size,) = struct.unpack_from("<I", data, 0)
    if header_size != HEADER_SIZE:
        raise ValueError(f"unexpected LNK header size {header_size:#x} (expected 0x4C)")

    link_flags = struct.unpack_from("<I", data, 0x14)[0]
    created_ft = struct.unpack_from("<Q", data, 0x1C)[0]
    accessed_ft = struct.unpack_from("<Q", data, 0x24)[0]
    modified_ft = struct.unpack_from("<Q", data, 0x2C)[0]
    file_size = struct.unpack_from("<I", data, 0x34)[0]
    show_cmd = struct.unpack_from("<I", data, 0x3C)[0]

    pos = HEADER_SIZE
    if link_flags & HAS_LINK_TARGET_ID_LIST:
        if pos + 2 > len(data):
            raise ValueError("truncated LinkTargetIDList size")
        (idlist_size,) = struct.unpack_from("<H", data, pos)
        pos += 2 + idlist_size

    target_path = ""
    if link_flags & HAS_LINK_INFO and pos + 4 <= len(data):
        link_info_start = pos
        (link_info_size,) = struct.unpack_from("<I", data, link_info_start)
        (link_info_header_size,) = struct.unpack_from("<I", data, link_info_start + 4)
        (li_flags,) = struct.unpack_from("<I", data, link_info_start + 8)
        (local_base_path_offset,) = struct.unpack_from("<I", data, link_info_start + 0x10)

        local_base_path_offset_unicode = 0
        if link_info_header_size >= 0x24 and link_info_start + 0x1C <= len(data):
            local_base_path_offset_unicode = struct.unpack_from("<I", data, link_info_start + 0x1C)[0]

        volume_id_and_local_base_path = bool(li_flags & 0x1)
        if volume_id_and_local_base_path:
            if local_base_path_offset_unicode:
                target_path = _read_cstr_at(data, link_info_start + local_base_path_offset_unicode, unicode=True)
            elif local_base_path_offset:
                target_path = _read_cstr_at(data, link_info_start + local_base_path_offset, unicode=False)

        pos = link_info_start + link_info_size

    created_dt = filetime_to_datetime(created_ft)
    accessed_dt = filetime_to_datetime(accessed_ft)
    modified_dt = filetime_to_datetime(modified_ft)

    return LnkInfo(
        target_path=target_path,
        target_size=file_size,
        target_created=created_dt.isoformat() if created_dt else None,
        target_accessed=accessed_dt.isoformat() if accessed_dt else None,
        target_modified=modified_dt.isoformat() if modified_dt else None,
        show_command=show_cmd,
    )

# ======================================================================
# ---- from parsers/usn.py ----
# ======================================================================
"""
usn.py — parses NTFS USN Journal records ($UsnJrnl:$J), shared by both
PathsParser++ and JournalTrace++ (they're the same underlying data —
PathsParser++ is the general path/timeline view, JournalTrace++ is the
same records with reason/keyword filtering).

The USN Journal itself lives in an NTFS alternate data stream
($UsnJrnl:$J) which isn't accessible as a normal file — you need to
export it first, e.g.:

  fsutil usn readjournal C: > usn_dump.bin        (Windows built-in)

...or with a forensic imaging tool. Point this parser at that exported
file.

Record format (USN_RECORD_V2 — the common version; V3/V4 use 128-bit
file IDs and aren't handled here):
  RecordLength (u32), MajorVersion (u16), MinorVersion (u16),
  FileReferenceNumber (u64), ParentFileReferenceNumber (u64),
  Usn (u64), TimeStamp (u64 FILETIME), Reason (u32), SourceInfo (u32),
  SecurityId (u32), FileAttributes (u32),
  FileNameLength (u16), FileNameOffset (u16), FileName (variable, UTF-16LE)

This is Microsoft's own published structure (MS-FSCC / fsutil docs) —
HIGH confidence, verified here against a hand-built synthetic record
(test_usn_synthetic.py). The journal is a sparse, page-aligned file with
runs of zero padding between valid records; this parser skips zero
padding and resyncs on the next plausible record rather than assuming
records are perfectly back-to-back.
"""


REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x00400000, "TRANSACTED_CHANGE"),
    (0x80000000, "CLOSE"),
]


def decode_reason(flags: int) -> str:
    names = [name for bit, name in REASON_FLAGS if flags & bit]
    return "|".join(names) if names else f"0x{flags:08x}"


@dataclass
class UsnRecord:
    usn: int
    timestamp: Optional[str]
    reason: str
    file_name: str
    file_reference: int
    parent_reference: int
    file_attributes: int


def parse_usn_journal(path: str, max_records: int = 200000) -> List[UsnRecord]:
    with open(path, "rb") as f:
        data = f.read()

    records = []
    pos = 0
    n = len(data)
    while pos + 4 <= n and len(records) < max_records:
        (record_length,) = struct.unpack_from("<I", data, pos)

        if record_length == 0:
            # zero padding between records — resync by scanning forward
            # in small steps rather than assuming a fixed page size
            pos += 8
            continue
        if record_length < 60 or pos + record_length > n:
            # implausible length — likely mid-padding noise; step forward
            # and keep looking for the next plausible record boundary
            pos += 8
            continue

        try:
            major_version = struct.unpack_from("<H", data, pos + 4)[0]
            if major_version != 2:
                pos += 8
                continue
            file_ref = struct.unpack_from("<Q", data, pos + 8)[0]
            parent_ref = struct.unpack_from("<Q", data, pos + 16)[0]
            usn = struct.unpack_from("<Q", data, pos + 24)[0]
            timestamp_ft = struct.unpack_from("<Q", data, pos + 32)[0]
            reason = struct.unpack_from("<I", data, pos + 40)[0]
            file_attrs = struct.unpack_from("<I", data, pos + 52)[0]
            name_len, name_off = struct.unpack_from("<HH", data, pos + 56)

            name = ""
            if name_off and name_len and pos + name_off + name_len <= n:
                name = data[pos + name_off: pos + name_off + name_len].decode("utf-16-le", errors="ignore")

            dt = filetime_to_datetime(timestamp_ft)
            records.append(UsnRecord(
                usn=usn,
                timestamp=dt.isoformat() if dt else None,
                reason=decode_reason(reason),
                file_name=name,
                file_reference=file_ref & 0xFFFFFFFFFFFF,
                parent_reference=parent_ref & 0xFFFFFFFFFFFF,
                file_attributes=file_attrs,
            ))
        except struct.error:
            pos += 8
            continue

        pos += record_length
    return records

# ======================================================================
# ---- from parsers/minidump.py ----
# ======================================================================
"""
minidump.py — CrashedFileViewer++: reads the header and module list from a
Windows minidump (.dmp) crash file, e.g. from
C:\\Windows\\Minidump\\ or C:\\ProgramData\\Microsoft\\Windows\\WER\\.

SCOPE: this is triage-level, not a debugger. It reads:
  - the dump's creation timestamp
  - the list of every loaded module (EXE/DLL) at crash time, with base
    address, size, and that module's own PE compile timestamp

It does NOT parse the exception record, thread list/stack traces, or
memory contents — a full crash analysis needs a real debugger (WinDbg) or
a dedicated library; this gives you "what was loaded when it crashed",
which is the triage-relevant piece for spotting an unexpected module.

Format reference (Microsoft's own published MINIDUMP structures,
minidumpapiset.h): MINIDUMP_HEADER (32 bytes, signature "MDMP") followed
by a directory of MINIDUMP_DIRECTORY entries (stream type + size + RVA);
this reads the ModuleListStream (type 4) specifically. HIGH confidence on
the header/directory (small, stable struct); MODERATE on the module
record layout since minidump module records embed a VS_FIXEDFILEINFO
block whose internal fields aren't decoded here, only skipped over by
size — verified against a hand-built synthetic minidump in this build
(test_minidump_synthetic.py), not against a real Windows-produced .dmp.
"""


MDMP_SIGNATURE = b"MDMP"
STREAM_MODULE_LIST = 4

MODULE_RECORD_SIZE = 108  # bytes: fixed MINIDUMP_MODULE struct size


@dataclass
class ModuleEntry:
    base_of_image: int
    size_of_image: int
    module_name: str
    compile_time: Optional[str]


@dataclass
class MinidumpInfo:
    is_minidump: bool
    dump_created: Optional[str] = None
    number_of_streams: Optional[int] = None
    modules: List[ModuleEntry] = None


def _read_minidump_string(data: bytes, rva: int) -> str:
    if rva == 0 or rva + 4 > len(data):
        return ""
    (length,) = struct.unpack_from("<I", data, rva)  # length in bytes, no null terminator
    start = rva + 4
    end = start + length
    if end > len(data):
        return ""
    return data[start:end].decode("utf-16-le", errors="ignore")


def parse_minidump(path: str) -> MinidumpInfo:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 32 or data[0:4] != MDMP_SIGNATURE:
        return MinidumpInfo(is_minidump=False)

    version, number_of_streams, stream_dir_rva, checksum, timestamp = \
        struct.unpack_from("<IIIII", data, 4)

    dt = None
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        dt = None

    modules: List[ModuleEntry] = []
    for i in range(number_of_streams):
        entry_off = stream_dir_rva + i * 12
        if entry_off + 12 > len(data):
            break
        stream_type, data_size, rva = struct.unpack_from("<III", data, entry_off)
        if stream_type != STREAM_MODULE_LIST:
            continue
        if rva + 4 > len(data):
            continue
        (num_modules,) = struct.unpack_from("<I", data, rva)
        mod_pos = rva + 4
        for m in range(num_modules):
            if mod_pos + MODULE_RECORD_SIZE > len(data):
                break
            base_of_image = struct.unpack_from("<Q", data, mod_pos)[0]
            size_of_image = struct.unpack_from("<I", data, mod_pos + 8)[0]
            mod_timestamp = struct.unpack_from("<I", data, mod_pos + 16)[0]
            module_name_rva = struct.unpack_from("<I", data, mod_pos + 20)[0]

            mod_dt = None
            try:
                mod_dt = datetime.fromtimestamp(mod_timestamp, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                mod_dt = None

            modules.append(ModuleEntry(
                base_of_image=base_of_image,
                size_of_image=size_of_image,
                module_name=_read_minidump_string(data, module_name_rva),
                compile_time=mod_dt.isoformat() if mod_dt else None,
            ))
            mod_pos += MODULE_RECORD_SIZE
        break  # only one ModuleListStream is expected

    return MinidumpInfo(
        is_minidump=True,
        dump_created=dt.isoformat() if dt else None,
        number_of_streams=number_of_streams,
        modules=modules,
    )

# ======================================================================
# ---- from main.py ----
# ======================================================================
"""
deepchecks — registry/file artifact viewer (Amcache, BAM, Prefetch, MFT).

Stdlib only (Tkinter), so it runs with a plain `python main.py` — no pip
install needed for this stage. Point each tab at the relevant artifact:

  Amcache   -> C:\\Windows\\AppCompat\\Programs\\Amcache.hve
  BAM       -> C:\\Windows\\System32\\config\\SYSTEM  (live copy needs a
               shadow-copy / offline export tool — the hive is locked
               while Windows is running)
  Prefetch  -> a single .pf file from C:\\Windows\\Prefetch\\
  MFT       -> an already-extracted $MFT file (see parsers/mft.py docstring)
  Browsing History -> Chrome/Edge/Brave "History" file, or Firefox
               "places.sqlite" (auto-detected either way) — from e.g.
               %LocalAppData%\\Google\\Chrome\\User Data\\Default\\History
               or %AppData%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite
  Downloads History -> same files as Browsing History, different tab

Every parser module also runs standalone from the command line — see the
`if __name__ == "__main__"` block at the bottom of each parsers/*.py file.
"""





class ResultTable(ttk.Frame):
    """A file-picker + status bar + sortable Treeview + CSV export, reused
    across all four tabs."""

    def __init__(self, parent, columns, load_fn, picker_kind="open"):
        super().__init__(parent, padding=10)
        self.columns = columns
        self.load_fn = load_fn
        self.picker_kind = picker_kind
        self._rows = []

        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Choose file…", command=self._choose).pack(side="left")
        self.path_var = tk.StringVar(value="No file selected")
        ttk.Label(top, textvariable=self.path_var, foreground="#666").pack(side="left", padx=10)
        ttk.Button(top, text="Export CSV", command=self._export).pack(side="right")

        self.status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status_var, foreground="#a13").pack(fill="x", anchor="w")

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for c in columns:
            self.tree.heading(c, text=c, command=lambda c=c: self._sort_by(c))
            self.tree.column(c, width=140, anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

    def _choose(self):
        if self.picker_kind == "open":
            path = filedialog.askopenfilename(title="Select artifact file")
        else:
            path = filedialog.askopenfilename(title="Select file")
        if not path:
            return
        self.path_var.set(path)
        self.status_var.set("")
        self.tree.delete(*self.tree.get_children())
        self._rows = []
        try:
            self._rows = self.load_fn(path)
        except PrefetchError as e:
            self.status_var.set(str(e))
            return
        except Exception as e:
            self.status_var.set(f"Failed to parse: {e}")
            traceback.print_exc()
            return
        for row in self._rows:
            self.tree.insert("", "end", values=[row.get(c, "") for c in self.columns])
        self.status_var.set(f"{len(self._rows)} rows" if self._rows else "Parsed OK — 0 rows found")

    def _sort_by(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda t: t[0].lower())
        except AttributeError:
            items.sort()
        for i, (_, k) in enumerate(items):
            self.tree.move(k, "", i)

    def _export(self):
        if not self._rows:
            messagebox.showinfo("Export CSV", "Nothing to export yet — load a file first.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not out:
            return
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self.columns)
            w.writeheader()
            w.writerows(self._rows)
        messagebox.showinfo("Export CSV", f"Saved {len(self._rows)} rows to {out}")


def _load_amcache(path):
    return [{
        "path": e.path, "sha1": e.sha1, "size": e.size, "product_name": e.product_name,
        "publisher": e.publisher, "link_date": e.link_date, "key_last_write": e.key_last_write,
        "schema": e.schema,
    } for e in parse_amcache(path)]


def _load_bam(path):
    return [{
        "sid": e.sid, "path": e.path, "last_run": e.last_run, "control_set": e.control_set,
    } for e in parse_bam(path)]


def _load_prefetch(path):
    info = parse_prefetch(path)
    rows = [{
        "executable_name": info.executable_name, "hash": info.prefetch_hash,
        "version": info.version, "run_count": info.run_count,
        "last_run": t, "volume_count": info.volume_count,
        "confidence": info.timestamps_confidence,
    } for t in (info.last_run_times or [None])]
    for f in info.referenced_files[:500]:
        rows.append({"executable_name": info.executable_name, "hash": info.prefetch_hash,
                      "version": info.version, "run_count": "", "last_run": "",
                      "volume_count": f"referenced: {f}", "confidence": ""})
    return rows


def _load_mft(path):
    rows = []
    for r in parse_mft(path):
        if not r.file_names and not r.damaged:
            continue
        rows.append({
            "record#": r.record_number, "in_use": r.in_use, "is_dir": r.is_directory,
            "name": r.best_name, "parent_record": r.file_names[0].parent_record if r.file_names else "",
            "si_created": r.si_created, "si_modified": r.si_modified, "si_accessed": r.si_accessed,
            "data_size": r.data_real_size, "damaged": r.damaged,
        })
        if len(rows) >= 20000:  # keep the GUI responsive on large $MFT files
            break
    return rows


def _load_browsing_history(path):
    return [{
        "browser": e.browser, "url": e.url, "title": e.title,
        "visit_time": e.visit_time, "visit_count": e.visit_count,
    } for e in parse_browsing_history(path)]


def _load_downloads_history(path):
    return [{
        "browser": e.browser, "path": e.path, "source_url": e.source_url,
        "start_time": e.start_time, "end_time": e.end_time, "received_bytes": e.received_bytes,
        "total_bytes": e.total_bytes, "state": e.state, "confidence": e.confidence,
    } for e in parse_downloads_history(path)]


def _load_usb(path):
    return [{
        "enum_path": e.enum_path, "device_type": e.device_type, "instance_id": e.instance_id,
        "friendly_name": e.friendly_name, "device_desc": e.device_desc, "mfg": e.mfg,
        "last_key_write": e.last_key_write, "confidence": e.confidence,
    } for e in parse_usb(path)]


def _load_powershell(path):
    return [{"line_number": e.line_number, "command": e.command} for e in parse_psreadline_history(path)]


def _load_stringexplorer(path):
    fa = analyze_file(path)
    rows = [{
        "type": "summary", "value": f"size={fa.size} sha256={fa.sha256} entropy={fa.entropy} "
                                     f"pe_compile_time={fa.pe.compile_time} pe_machine={fa.pe.machine}",
    }]
    for s in fa.ascii_strings[:2000]:
        rows.append({"type": "ascii_string", "value": s})
    for s in fa.wide_strings[:2000]:
        rows.append({"type": "wide_string", "value": s})
    return rows


def _load_savedfiles(path):
    info = parse_lnk(path)
    return [{
        "target_path": info.target_path, "target_size": info.target_size,
        "target_created": info.target_created, "target_accessed": info.target_accessed,
        "target_modified": info.target_modified, "show_command": info.show_command,
    }]


def _load_usn(path):
    return [{
        "usn": e.usn, "timestamp": e.timestamp, "reason": e.reason, "file_name": e.file_name,
        "file_reference": e.file_reference, "parent_reference": e.parent_reference,
        "file_attributes": e.file_attributes,
    } for e in parse_usn_journal(path)]


def _load_crashedfile(path):
    info = parse_minidump(path)
    if not info.is_minidump:
        return [{"module_name": "NOT A MINIDUMP FILE", "base_of_image": "", "size_of_image": "", "compile_time": ""}]
    rows = [{"module_name": f"[dump created: {info.dump_created}, streams: {info.number_of_streams}]",
              "base_of_image": "", "size_of_image": "", "compile_time": ""}]
    for m in info.modules:
        rows.append({
            "module_name": m.module_name, "base_of_image": hex(m.base_of_image),
            "size_of_image": m.size_of_image, "compile_time": m.compile_time,
        })
    return rows


def build_app():
    root = tk.Tk()
    root.title("deepchecks — artifact viewer")
    root.geometry("1040x620")

    banner = ttk.Label(
        root,
        text="Registry/file-artifact stage: Amcache + BAM parsing follow the documented "
             "hive format directly. Prefetch and MFT timestamp offsets are version-gated "
             "best-effort — verify against PECmd / MFTECmd on real data before relying on them.",
        wraplength=1020, foreground="#a13", padding=8, justify="left",
    )
    banner.pack(fill="x")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True)

    amcache_tab = ResultTable(nb, ["path", "sha1", "size", "product_name", "publisher",
                                    "link_date", "key_last_write", "schema"], _load_amcache)
    bam_tab = ResultTable(nb, ["sid", "path", "last_run", "control_set"], _load_bam)
    prefetch_tab = ResultTable(nb, ["executable_name", "hash", "version", "run_count",
                                     "last_run", "volume_count", "confidence"], _load_prefetch)
    mft_tab = ResultTable(nb, ["record#", "in_use", "is_dir", "name", "parent_record",
                                 "si_created", "si_modified", "si_accessed", "data_size", "damaged"], _load_mft)
    history_tab = ResultTable(nb, ["browser", "url", "title", "visit_time", "visit_count"], _load_browsing_history)
    downloads_tab = ResultTable(nb, ["browser", "path", "source_url", "start_time", "end_time",
                                       "received_bytes", "total_bytes", "state", "confidence"], _load_downloads_history)
    usb_tab = ResultTable(nb, ["enum_path", "device_type", "instance_id", "friendly_name",
                                 "device_desc", "mfg", "last_key_write", "confidence"], _load_usb)
    powershell_tab = ResultTable(nb, ["line_number", "command"], _load_powershell)
    stringexplorer_tab = ResultTable(nb, ["type", "value"], _load_stringexplorer)
    savedfiles_tab = ResultTable(nb, ["target_path", "target_size", "target_created",
                                        "target_accessed", "target_modified", "show_command"], _load_savedfiles)
    pathsparser_tab = ResultTable(nb, ["usn", "timestamp", "reason", "file_name", "file_reference",
                                         "parent_reference", "file_attributes"], _load_usn)
    journaltrace_tab = ResultTable(nb, ["usn", "timestamp", "reason", "file_name", "file_reference",
                                          "parent_reference", "file_attributes"], _load_usn)
    crashedfile_tab = ResultTable(nb, ["module_name", "base_of_image", "size_of_image", "compile_time"], _load_crashedfile)

    nb.add(amcache_tab, text="Amcache")
    nb.add(bam_tab, text="BAM")
    nb.add(prefetch_tab, text="Prefetch")
    nb.add(mft_tab, text="MFT")
    nb.add(history_tab, text="Browsing History")
    nb.add(downloads_tab, text="Downloads History")
    nb.add(usb_tab, text="USB Devices")
    nb.add(powershell_tab, text="PowerShell History")
    nb.add(stringexplorer_tab, text="String Explorer")
    nb.add(savedfiles_tab, text="Saved Files (LNK)")
    nb.add(pathsparser_tab, text="Paths Parser")
    nb.add(journaltrace_tab, text="Journal Trace")
    nb.add(crashedfile_tab, text="Crashed File Viewer")

    return root


if __name__ == "__main__":
    app = build_app()
    app.mainloop()