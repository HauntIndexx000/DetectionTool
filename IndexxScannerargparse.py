import argparse
import ctypes
import hashlib
import json
import logging
import shutil
import sys
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("Missing dependency: pip install psutil")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAVE_WATCHDOG = True
except ImportError:
    HAVE_WATCHDOG = False                         

                                                                        
                                                                     
                                                                      
                                               
                                                                        

GAME_EXE_NAMES = {"gorilla tag.exe", "gorillatag.exe"}

                                                                  
                                                                      
                                                                       
                                                        
PROXY_DLL_NAMES = {
    "winmm.dll", "version.dll", "winhttp.dll", "dbghelp.dll",
    "d3d9.dll", "dinput8.dll", "xinput1_3.dll",
}

LOADER_DIR_NAMES = {"bepinex", "melonloader", "mlmods", "plugins"}
LOADER_FILE_NAMES = {
    "doorstop_config.ini", "winhttp.dll.orig", "changelog.txt",
}

                                                                    
                                                                       
                                                                   
                                                                 
                                     
SUSPECT_PROC_NAMES = {
    "nssm.exe", "srvany.exe", "srvstart.exe", "regis.exe",
    "inj.exe", "apphost.exe",
}
AMBIGUOUS_PROC_NAMES = {"svchost.exe", "msedge.exe"}
LEGIT_DIRS_FOR_AMBIGUOUS = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files (x86)\microsoft\edge\application",
    r"c:\program files\microsoft\edge\application",
}

QUARANTINE_DIRNAME = "_gtag_anticheat_quarantine"
LOG_FILE = "gtag_anticheat.log"

                                                                        

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("gtag_anticheat")


def sha256_of(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"<unreadable: {e}>"


class Quarantine:
    """Moves flagged files into a quarantine folder instead of deleting
    outright, so you can inspect what was caught before it's gone."""

    def __init__(self, game_dir: Path):
        self.dir = game_dir / QUARANTINE_DIRNAME
        self.dir.mkdir(exist_ok=True)
        self.manifest_path = self.dir / "manifest.jsonl"

    def take(self, path: Path, reason: str):
        try:
            digest = sha256_of(path)
            dest = self.dir / f"{int(time.time())}_{path.name}"
            if path.is_dir():
                shutil.move(str(path), str(dest))
            else:
                shutil.move(str(path), str(dest))
            entry = {
                "timestamp": datetime.now().isoformat(),
                "original_path": str(path),
                "quarantined_to": str(dest),
                "reason": reason,
                "sha256": digest,
            }
            with open(self.manifest_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            log.warning("QUARANTINED %s -> %s (%s)", path, dest, reason)
        except Exception as e:
            log.error("Failed to quarantine %s: %s", path, e)


def scan_game_dir(game_dir: Path, quarantine: Quarantine):
    """One-shot sweep of the install directory for loader artifacts."""
    hits = []

    for entry in game_dir.iterdir():
        name_lower = entry.name.lower()

        if entry.is_dir() and name_lower in LOADER_DIR_NAMES:
            hits.append(entry)
            continue

        if entry.is_file():
            if name_lower in LOADER_FILE_NAMES:
                hits.append(entry)
                continue
            if name_lower in PROXY_DLL_NAMES:
                                                                    
                                                                        
                                                                        
                                                                         
                                                                        
                hits.append(entry)
                continue

    for path in hits:
        quarantine.take(path, "loader artifact match")

    if not hits:
        log.info("Game dir sweep clean: %s", game_dir)
    return hits


class DirWatchHandler(FileSystemEventHandler if HAVE_WATCHDOG else object):
    def __init__(self, game_dir: Path, quarantine: Quarantine):
        self.game_dir = game_dir
        self.quarantine = quarantine

    def on_created(self, event):
        path = Path(event.src_path)
        name_lower = path.name.lower()
        if event.is_directory and name_lower in LOADER_DIR_NAMES:
            self.quarantine.take(path, "loader dir created")
        elif not event.is_directory and (
            name_lower in LOADER_FILE_NAMES or name_lower in PROXY_DLL_NAMES
        ):
            self.quarantine.take(path, "loader file created")


                                                                        
                                    
                                                                        

def enum_process_modules(pid: int):
    """Returns a list of (module_name, full_path) for a process using
    psutil, which wraps the Windows toolhelp/PSAPI calls for you."""
    try:
        p = psutil.Process(pid)
                                                                       
                                                                        
        return _enum_modules_ctypes(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []


def _enum_modules_ctypes(pid: int):
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    LIST_MODULES_ALL = 0x03

    psapi = ctypes.WinDLL("Psapi.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    h_process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h_process:
        return []

    modules = []
    try:
        arr_size = 1024
        h_mods = (wintypes.HMODULE * arr_size)()
        needed = wintypes.DWORD()

        if not psapi.EnumProcessModulesEx(
            h_process, ctypes.byref(h_mods), ctypes.sizeof(h_mods),
            ctypes.byref(needed), LIST_MODULES_ALL
        ):
            return []

        count = min(arr_size, needed.value // ctypes.sizeof(wintypes.HMODULE))
        for i in range(count):
            buf = ctypes.create_unicode_buffer(260)
            psapi.GetModuleFileNameExW(h_process, h_mods[i], buf, 260)
            full_path = buf.value
            if full_path:
                modules.append((Path(full_path).name, full_path))
    finally:
        kernel32.CloseHandle(h_process)

    return modules


def check_game_process_modules(proc: psutil.Process, quarantine: Quarantine,
                                seen_flags: set, kill_on_detect: bool = False):
    """Returns True if the process was killed as a result of this check."""
    modules = enum_process_modules(proc.pid)
    for mod_name, mod_path in modules:
        mod_lower = mod_name.lower()
        key = (proc.pid, mod_lower)
        if key in seen_flags:
            continue

        flagged_reason = None
        if mod_lower in PROXY_DLL_NAMES:
                                                                         
                                                               
                                                                  
            if "system32" not in mod_path.lower() and "syswow64" not in mod_path.lower():
                flagged_reason = "proxy-DLL loaded from non-system path"
        if "bepinex" in mod_lower or "melonloader" in mod_lower or "doorstop" in mod_lower:
            flagged_reason = "known loader module name"

        if flagged_reason:
            seen_flags.add(key)
            log.warning(
                "INJECTED MODULE in PID %s (%s): %s @ %s [%s]",
                proc.pid, proc.name(), mod_name, mod_path, flagged_reason
            )
            if kill_on_detect:
                try:
                    proc.kill()
                    log.warning(
                        "KILLED Gorilla Tag (PID %s) due to detected injection: %s",
                        proc.pid, mod_name
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    log.error("Failed to kill PID %s: %s", proc.pid, e)
                return True
    return False


def scan_suspect_processes(log_findings: bool = True):
    """Returns a list of (name, pid, exe_path, reason) for anything flagged."""
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name_lower = (proc.info["name"] or "").lower()
            exe_path = (proc.info["exe"] or "").lower()

            if name_lower in SUSPECT_PROC_NAMES:
                findings.append((name_lower, proc.info["pid"], exe_path,
                                  "known injector-support process name"))

            elif name_lower in AMBIGUOUS_PROC_NAMES:
                exe_dir = str(Path(exe_path).parent) if exe_path else ""
                if not any(exe_dir.startswith(d) for d in LEGIT_DIRS_FOR_AMBIGUOUS):
                    findings.append((name_lower, proc.info["pid"], exe_path,
                                      "masquerading as system/Edge process from unexpected path"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if log_findings:
        for name, pid, exe_path, reason in findings:
            log.warning("Suspect process: %s (pid %s) exe=%s [%s]", name, pid, exe_path, reason)

    return findings


def preflight_gate(game_dir: Path, quarantine: Quarantine) -> list:
    """Sweeps the install dir and process list BEFORE launch. Returns a
    list of human-readable blocker strings; empty list means clean."""
    blockers = []

    dir_hits = scan_game_dir(game_dir, quarantine)
    if dir_hits:
        blockers.append(
            f"{len(dir_hits)} loader artifact(s) found and quarantined in the install dir: "
            + ", ".join(h.name for h in dir_hits)
        )

    if find_game_process():
        blockers.append(
            "Gorilla Tag is already running -- close it first so re-checking the "
            "install dir and process list is meaningful."
        )

    proc_findings = scan_suspect_processes()
    for name, pid, exe_path, reason in proc_findings:
        blockers.append(f"suspect process running: {name} (pid {pid}) - {reason}")

    return blockers


def launch_game(exe_path: Path):
    import subprocess
    log.info("Launching %s", exe_path)
    return subprocess.Popen([str(exe_path)], cwd=str(exe_path.parent))


def find_game_process():
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if (proc.info["name"] or "").lower() in GAME_EXE_NAMES:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


                                                                        

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-dir", required=True,
                         help="Path to the Gorilla Tag install directory")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                         help="Seconds between process/module scans")
    parser.add_argument("--no-quarantine", action="store_true",
                         help="Log detections only, don't move files")
    parser.add_argument("--launch", action="store_true",
                         help="Gate + launch the game: refuse to start it if the "
                              "pre-flight sweep finds anything, then launch it yourself")
    parser.add_argument("--exe", default=None,
                         help="Full path to Gorilla Tag.exe (required with --launch)")
    parser.add_argument("--kill-on-detect", dest="kill_on_detect", action="store_true",
                         default=None,
                         help="Kill the game process immediately if an injected module is "
                              "found post-launch. Defaults to ON with --launch, OFF otherwise.")
    args = parser.parse_args()

    if sys.platform != "win32":
        sys.exit("This script targets Windows (Gorilla Tag PC). Not supported on this OS.")

    game_dir = Path(args.game_dir).resolve()
    if not game_dir.is_dir():
        sys.exit(f"Game dir not found: {game_dir}")

                                                                              
                                                                        
    kill_on_detect = args.kill_on_detect if args.kill_on_detect is not None else args.launch

    quarantine = Quarantine(game_dir)

    if args.launch:
        if not args.exe:
            sys.exit("--launch requires --exe \"<path to Gorilla Tag.exe>\"")
        exe_path = Path(args.exe).resolve()
        if not exe_path.is_file():
            sys.exit(f"--exe path not found: {exe_path}")

        log.info("Pre-flight gate: sweeping install dir and process list before launch...")
        blockers = preflight_gate(game_dir, quarantine)
        if blockers:
            log.error("LAUNCH BLOCKED -- Gorilla Tag will NOT be started. Reasons:")
            for b in blockers:
                log.error("  - %s", b)
            log.error("Resolve the above (close flagged processes, re-run) and try again.")
            sys.exit(1)

        log.info("Pre-flight clean. Launching Gorilla Tag.")
        launch_game(exe_path)

                                                                     
                        
        time.sleep(1.5)
    else:
        log.info("Starting initial sweep of %s", game_dir)
        scan_game_dir(game_dir, quarantine)

    observer = None
    if HAVE_WATCHDOG:
        handler = DirWatchHandler(game_dir, quarantine)
        observer = Observer()
        observer.schedule(handler, str(game_dir), recursive=False)
        observer.start()
        log.info("Filesystem watchdog active on %s", game_dir)
    else:
        log.warning("watchdog not installed (pip install watchdog) -- "
                     "falling back to periodic directory polling only")

    seen_flags = set()
    log.info(
        "Watching for Gorilla Tag process + suspect processes (interval=%.1fs, "
        "kill_on_detect=%s). Ctrl+C to stop.",
        args.poll_interval, kill_on_detect
    )

    try:
        while True:
            if not HAVE_WATCHDOG:
                scan_game_dir(game_dir, quarantine)

            proc = find_game_process()
            if proc:
                killed = check_game_process_modules(proc, quarantine, seen_flags, kill_on_detect)
                if killed and args.launch:
                    log.error(
                        "Gorilla Tag was terminated because an injected module was detected "
                        "after launch. Re-run this script to relaunch once your setup is clean."
                    )
                    break
            elif args.launch:
                                                                                  
                log.info("Gorilla Tag process is no longer running. Exiting.")
                break

            scan_suspect_processes()
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        log.info("Stopping.")
    finally:
        if observer:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    main()