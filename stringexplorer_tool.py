"""
StringExplorer++ (standalone) — PE strings, entropy, compile date, optional VirusTotal.
Run with no args for a GUI file picker, or: python3 stringexplorer_tool.py file.exe out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile, hashlib, json, math, re
import urllib.request, urllib.error
from urllib.parse import unquote, urlparse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta, timezone


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



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['type', 'value'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('StringExplorer++ (standalone)', ['type', 'value'], _load_rows)