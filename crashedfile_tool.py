"""
CrashedFileViewer++ (standalone) — minidump header + module list triage.
Run with no args for a GUI file picker, or: python3 crashedfile_tool.py file.dmp out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile, hashlib, json, math, re
import urllib.request, urllib.error
from urllib.parse import unquote, urlparse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta, timezone


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



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['module_name', 'base_of_image', 'size_of_image', 'compile_time'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('CrashedFileViewer++ (standalone)', ['module_name', 'base_of_image', 'size_of_image', 'compile_time'], _load_rows)