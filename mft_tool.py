"""
MFTExplorer++ (standalone) — parses an already-extracted NTFS $MFT file.
Run with no args for a GUI file picker, or: python3 mft_tool.py extracted_MFT out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile
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
        if len(rows) >= 20000:
            break
    return rows



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['record#', 'in_use', 'is_dir', 'name', 'parent_record', 'si_created', 'si_modified', 'si_accessed', 'data_size', 'damaged'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('MFTExplorer++ (standalone)', ['record#', 'in_use', 'is_dir', 'name', 'parent_record', 'si_created', 'si_modified', 'si_accessed', 'data_size', 'damaged'], _load_rows)