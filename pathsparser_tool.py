"""
PathsParser++ (standalone) — general USN Journal path/timeline viewer.
Run with no args for a GUI file picker, or: python3 pathsparser_tool.py usn_dump.bin out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile, hashlib, json, math, re
import urllib.request, urllib.error
from urllib.parse import unquote, urlparse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta, timezone


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


# ----------------------------------------------------------------------
# Minimal standalone Tkinter GUI — file picker + results table + CSV export
# ----------------------------------------------------------------------
def _run_gui(title, columns, load_fn):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title(title)
    root.geometry("980x560")

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    path_var = tk.StringVar(value="No file selected")
    status_var = tk.StringVar(value="")
    rows_holder = {"rows": []}

    tree_frame = ttk.Frame(root, padding=(10, 0, 10, 10))
    tree_frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
    for c in columns:
        tree.heading(c, text=c)
        tree.column(c, width=140, anchor="w")
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    tree_frame.rowconfigure(0, weight=1)
    tree_frame.columnconfigure(0, weight=1)

    def choose():
        path = filedialog.askopenfilename(title="Select artifact file")
        if not path:
            return
        path_var.set(path)
        status_var.set("")
        tree.delete(*tree.get_children())
        try:
            rows = load_fn(path)
        except Exception as e:
            status_var.set(f"Failed to parse: {e}")
            return
        rows_holder["rows"] = rows
        for row in rows:
            tree.insert("", "end", values=[row.get(c, "") for c in columns])
        status_var.set(f"{len(rows)} rows" if rows else "Parsed OK — 0 rows found")

    def export():
        rows = rows_holder["rows"]
        if not rows:
            messagebox.showinfo("Export CSV", "Nothing to export yet — load a file first.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not out:
            return
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=columns)
            w.writeheader()
            w.writerows(rows)
        messagebox.showinfo("Export CSV", f"Saved {len(rows)} rows to {out}")

    ttk.Button(top, text="Choose file…", command=choose).pack(side="left")
    ttk.Label(top, textvariable=path_var, foreground="#666").pack(side="left", padx=10)
    ttk.Button(top, text="Export CSV", command=export).pack(side="right")
    ttk.Label(root, textvariable=status_var, foreground="#a13", padding=(10, 0)).pack(fill="x", anchor="w")

    root.mainloop()



def _load_rows(path):
    return [{
        "usn": e.usn, "timestamp": e.timestamp, "reason": e.reason, "file_name": e.file_name,
        "file_reference": e.file_reference, "parent_reference": e.parent_reference,
        "file_attributes": e.file_attributes,
    } for e in parse_usn_journal(path)]



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['usn', 'timestamp', 'reason', 'file_name', 'file_reference', 'parent_reference', 'file_attributes'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('PathsParser++ (standalone)', ['usn', 'timestamp', 'reason', 'file_name', 'file_reference', 'parent_reference', 'file_attributes'], _load_rows)