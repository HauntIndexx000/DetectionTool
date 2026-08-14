"""
BrowsingHistoryView++ (standalone) — Chromium/Firefox browsing history.
Run with no args for a GUI file picker, or: python3 browsing_history_tool.py History out.csv
"""

import struct, os, sys, csv, ctypes, sqlite3, shutil, tempfile
from urllib.parse import unquote, urlparse
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timedelta, timezone


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
        "browser": e.browser, "url": e.url, "title": e.title,
        "visit_time": e.visit_time, "visit_count": e.visit_count,
    } for e in parse_browsing_history(path)]



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['browser', 'url', 'title', 'visit_time', 'visit_count'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('BrowsingHistoryView++ (standalone)', ['browser', 'url', 'title', 'visit_time', 'visit_count'], _load_rows)