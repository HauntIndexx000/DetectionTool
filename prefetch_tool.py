"""
WinPrefetchView++ (standalone) — parses a single Windows .pf prefetch file.
Run with no args for a GUI file picker, or: python3 prefetch_tool.py file.pf out.csv
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



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['executable_name', 'hash', 'version', 'run_count', 'last_run', 'volume_count', 'confidence'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('WinPrefetchView++ (standalone)', ['executable_name', 'hash', 'version', 'run_count', 'last_run', 'volume_count', 'confidence'], _load_rows)