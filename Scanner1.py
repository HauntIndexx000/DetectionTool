#!/usr/bin/env python3
"""
gtag_cheat_scanner.py

Scans running processes and Windows Scheduled Tasks for known Gorilla Tag
injector / mod-menu loader process names, using regex matching.

Detection sources:
  1. Running processes (via psutil)
  2. Scheduled Tasks (via `schtasks /query`)

Because some flagged names (svchost, AppHost) are also legitimate Windows
system processes, those two are treated as "ambiguous" — they only get
flagged if their executable path looks suspicious (i.e. NOT running from
System32/SysWOW64, which is where the real ones always live).

Usage:
    python gtag_cheat_scanner.py
    python gtag_cheat_scanner.py --log scan_report.txt
    python gtag_cheat_scanner.py --interval 5      # continuous monitor mode

Requires: psutil  (pip install psutil)
Windows only for the scheduled-task scan (uses schtasks.exe); process
scanning works cross-platform.
"""

import re
import sys
import time
import argparse
import subprocess
import datetime as dt
from pathlib import Path

try:
    import psutil
except ImportError:
    print("This script requires psutil. Install it with:\n  pip install psutil")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Known injector / cheat-loader names
# ---------------------------------------------------------------------------
# Names here are matched as whole process names (case-insensitive), with or
# without a .exe suffix. Add new patterns as you find them — regex lets you
# catch variants (e.g. "srvany64", "inj_loader", "regis-v2") without needing
# an exact string per entry.

KNOWN_PATTERNS = [
    r"^nssm(\.exe)?$",
    r"^srvany(64)?(\.exe)?$",
    r"^srvstart(\.exe)?$",
    r"^regis[\w\-]*(\.exe)?$",
    r"^inj[\w\-]*(\.exe)?$",       # catches inj, injector, inj_loader, etc.
    r"^apphost(\.exe)?$",          # AMBIGUOUS — see AMBIGUOUS_NAMES below
    r"^svchost(\.exe)?$",          # AMBIGUOUS — see AMBIGUOUS_NAMES below
    r"^msedge(\.exe)?$",           # legit browser, but abused as a disguise name
]

# Names that are also legitimate Windows components. For these, only flag
# if the executable is NOT running from an expected system directory.
AMBIGUOUS_NAMES = {"svchost.exe", "svchost", "apphost.exe", "apphost"}

# Legit install locations for the ambiguous names (lowercased, partial match)
LEGIT_DIRS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
]

# msedge.exe is legit almost everywhere it normally installs; flag it only
# as a low-confidence "watch" note, not a hard hit, unless path is bizarre.
WATCH_ONLY_NAMES = {"msedge.exe", "msedge"}

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in KNOWN_PATTERNS]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, source, name, detail, confidence, extra=""):
        self.source = source          # "process" or "scheduled_task"
        self.name = name
        self.detail = detail          # pid/path or task name
        self.confidence = confidence  # "HIGH", "MEDIUM", "WATCH"
        self.extra = extra

    def __str__(self):
        return f"[{self.confidence:6}] ({self.source}) {self.name} — {self.detail} {self.extra}".rstrip()


# ---------------------------------------------------------------------------
# Process scanning
# ---------------------------------------------------------------------------

def name_matches(name: str):
    """Return the matching pattern string, or None."""
    for pat in COMPILED_PATTERNS:
        if pat.match(name):
            return pat.pattern
    return None


def is_legit_path(exe_path: str) -> bool:
    if not exe_path:
        return False
    lowered = exe_path.lower()
    return any(lowered.startswith(d) for d in LEGIT_DIRS)


def scan_processes():
    findings = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            if not name:
                continue

            pattern = name_matches(name)
            if not pattern:
                continue

            exe_path = info.get("exe") or ""
            pid = info.get("pid")
            cmdline = " ".join(info.get("cmdline") or [])

            lname = name.lower()

            if lname in AMBIGUOUS_NAMES:
                if is_legit_path(exe_path):
                    continue  # genuine system process, skip
                findings.append(Finding(
                    "process", name,
                    f"PID {pid} | path: {exe_path or 'unknown'}",
                    "HIGH",
                    extra=f"| cmdline: {cmdline}" if cmdline else "(path outside System32 — suspicious)"
                ))
            elif lname in WATCH_ONLY_NAMES:
                findings.append(Finding(
                    "process", name,
                    f"PID {pid} | path: {exe_path or 'unknown'}",
                    "WATCH",
                    extra="(legit browser name, but verify path/publisher)"
                ))
            else:
                findings.append(Finding(
                    "process", name,
                    f"PID {pid} | path: {exe_path or 'unknown'}",
                    "HIGH",
                    extra=f"| cmdline: {cmdline}" if cmdline else ""
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return findings


# ---------------------------------------------------------------------------
# Scheduled task scanning (Windows only)
# ---------------------------------------------------------------------------

def scan_scheduled_tasks():
    findings = []
    if sys.platform != "win32":
        return findings

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True, text=True, timeout=30
        )
    except Exception as e:
        print(f"(scheduled task scan skipped: {e})")
        return findings

    if result.returncode != 0:
        return findings

    # Split into per-task blocks on the "TaskName:" field
    blocks = re.split(r"(?=^TaskName:)", result.stdout, flags=re.MULTILINE)
    for block in blocks:
        task_name_match = re.search(r"^TaskName:\s*(.+)$", block, re.MULTILINE)
        task_run_match = re.search(r"^Task To Run:\s*(.+)$", block, re.MULTILINE)
        if not task_name_match or not task_run_match:
            continue

        task_name = task_name_match.group(1).strip()
        task_run = task_run_match.group(1).strip()

        # Pull just the executable filename out of the "Task To Run" command
        exe_candidate = Path(task_run.split()[0].strip('"')).name if task_run else ""

        pattern = name_matches(exe_candidate)
        if not pattern:
            continue

        lname = exe_candidate.lower()
        if lname in AMBIGUOUS_NAMES:
            # scheduled tasks legitimately calling svchost/apphost directly
            # is already unusual — flag it, but note ambiguity
            findings.append(Finding(
                "scheduled_task", exe_candidate,
                f"Task: {task_name} | Run: {task_run}",
                "MEDIUM",
                extra="(ambiguous name in a scheduled task is worth checking)"
            ))
        elif lname in WATCH_ONLY_NAMES:
            findings.append(Finding(
                "scheduled_task", exe_candidate,
                f"Task: {task_name} | Run: {task_run}",
                "WATCH"
            ))
        else:
            findings.append(Finding(
                "scheduled_task", exe_candidate,
                f"Task: {task_name} | Run: {task_run}",
                "HIGH"
            ))

    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def run_scan():
    findings = []
    findings.extend(scan_processes())
    findings.extend(scan_scheduled_tasks())
    return findings


def print_report(findings, log_path=None):
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"=== Gorilla Tag Cheat Scanner — {timestamp} ==="]

    if not findings:
        lines.append("No matches found.")
    else:
        high = [f for f in findings if f.confidence == "HIGH"]
        med = [f for f in findings if f.confidence == "MEDIUM"]
        watch = [f for f in findings if f.confidence == "WATCH"]

        if high:
            lines.append(f"\n-- HIGH confidence ({len(high)}) --")
            lines += [str(f) for f in high]
        if med:
            lines.append(f"\n-- MEDIUM confidence ({len(med)}) --")
            lines += [str(f) for f in med]
        if watch:
            lines.append(f"\n-- WATCH only ({len(watch)}) --")
            lines += [str(f) for f in watch]

    report = "\n".join(lines)
    print(report)

    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(report + "\n\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Scan for known Gorilla Tag injector/cheat process names.")
    parser.add_argument("--log", type=str, default=None, help="Append results to this log file.")
    parser.add_argument("--interval", type=float, default=None,
                         help="Repeat scan every N seconds (continuous monitor mode). Omit for a single scan.")
    args = parser.parse_args()

    if args.interval:
        print(f"Monitoring every {args.interval}s. Ctrl+C to stop.")
        try:
            while True:
                findings = run_scan()
                print_report(findings, args.log)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        findings = run_scan()
        print_report(findings, args.log)


if __name__ == "__main__":
    main()