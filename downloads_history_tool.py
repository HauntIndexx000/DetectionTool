"""
BrowserDownloadsView++ (standalone) — Chromium/Firefox download history.
Run with no args for a GUI file picker, or: python3 downloads_history_tool.py History out.csv
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
        "browser": e.browser, "path": e.path, "source_url": e.source_url,
        "start_time": e.start_time, "end_time": e.end_time, "received_bytes": e.received_bytes,
        "total_bytes": e.total_bytes, "state": e.state, "confidence": e.confidence,
    } for e in parse_downloads_history(path)]



if __name__ == "__main__":
    if len(sys.argv) > 1:
        rows = _load_rows(sys.argv[1])
        print(f"parsed {len(rows)} rows")
        if len(sys.argv) > 2:
            with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=['browser', 'path', 'source_url', 'start_time', 'end_time', 'received_bytes', 'total_bytes', 'state', 'confidence'])
                w.writeheader()
                w.writerows(rows)
    else:
        _run_gui('BrowserDownloadsView++ (standalone)', ['browser', 'path', 'source_url', 'start_time', 'end_time', 'received_bytes', 'total_bytes', 'state', 'confidence'], _load_rows)