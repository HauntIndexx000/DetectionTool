"""
PowerShellParser++ (standalone) — PSReadLine console history.
Run with no args for a GUI file picker, or: python3 powershell_tool.py ConsoleHost_history.txt out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile, hashlib, json, math, re
import urllib.request, urllib.error
from urllib.parse import unquote, urlparse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta, timezone


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
    return [{"line_number": e.line_number, "command": e.command} for e in parse_psreadline_history(path)]



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['line_number', 'command'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('PowerShellParser++ (standalone)', ['line_number', 'command'], _load_rows)