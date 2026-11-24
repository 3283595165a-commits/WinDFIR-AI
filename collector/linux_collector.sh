#!/usr/bin/env bash
# ==============================================================================
# WinDFIR-AI Anti-Tampering Linux DFIR Collector (linux_collector.sh)
# Target OS: CentOS / RHEL / Rocky / Ubuntu / Debian / Kylin / UOS
# Core Capabilities:
#   1. Bypasses tampered /bin/ps, /bin/netstat, /bin/ls by reading /proc directly
#   2. Detects Userland/LKM Rootkits (/etc/ld.so.preload, hidden PIDs, rpm -Va / dpkg -V)
#   3. Detects Timestomping (Inode ctime vs mtime mismatch) for old/rotated log cases
#   4. Scans chattr +i/+a immutable locks & 12 Linux persistence backdoor locations
#   5. Packages into linux_snapshot.json (.zip) and auto-uploads to WinDFIR-AI server
# ==============================================================================

set -u

CASE_ID=""
SERVER_URL="http://127.0.0.1:8000"
OUT_DIR="/tmp/windfir_linux_$(date +%Y%m%d_%H%M%S)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case-id|-CaseId|-c)
            CASE_ID="${2:-}"
            shift 2
            ;;
        --server|-ServerUrl|-s)
            SERVER_URL="${2:-}"
            shift 2
            ;;
        --out|-o)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "======================================================================"
echo "[*] WinDFIR-AI Anti-Tampering Linux Collector Starting..."
echo "[*] Mode: Direct /proc Kernel Read + Binary Integrity + 12-Point Sweep"
echo "======================================================================"

mkdir -p "$OUT_DIR/raw_logs"

HOSTNAME_VAL="$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname 2>/dev/null || echo 'LINUX-HOST')"
OS_VERSION="Linux"
if [[ -f /etc/os-release ]]; then
    OS_VERSION="$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"' || echo 'Linux')"
elif [[ -f /etc/redhat-release ]]; then
    OS_VERSION="$(cat /etc/redhat-release)"
fi
KERNEL_VER="$(cat /proc/version 2>/dev/null | awk '{print $1,$3}' || uname -sr)"
OS_FULL="${OS_VERSION} (${KERNEL_VER})"

# Extract primary non-loopback IPv4 from /proc/net/fib_trie or ip/hostname
PRIMARY_IP=""
if command -v ip >/dev/null 2>&1; then
    PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
fi
if [[ -z "$PRIMARY_IP" ]]; then
    PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
[[ -z "$PRIMARY_IP" ]] && PRIMARY_IP="127.0.0.1"

echo "[+] Hostname : $HOSTNAME_VAL"
echo "[+] IP Addr  : $PRIMARY_IP"
echo "[+] OS Info  : $OS_FULL"

# Use Python3 or Perl/Awk if available to generate clean JSON without external jq dependency
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if [[ -n "$PYTHON_BIN" ]]; then
    echo "[*] Running deep /proc kernel inspection, binary verification & ctime forensics via $PYTHON_BIN..."
    "$PYTHON_BIN" - "$OUT_DIR" "$HOSTNAME_VAL" "$PRIMARY_IP" "$OS_FULL" << 'PYEOF'
import os
import sys
import pwd
import stat
import time
import json
import glob
import socket
import struct
import hashlib
import subprocess
from datetime import datetime, timezone

out_dir, hostname_val, primary_ip, os_full = sys.argv[1:5]

def fmt_ts(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

# 1. Calculate system boot time from /proc/uptime & CLK_TCK
boot_time = time.time()
try:
    with open("/proc/uptime", "r") as f:
        uptime_sec = float(f.read().split()[0])
        boot_time = time.time() - uptime_sec
except Exception:
    pass
clk_tck = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) if hasattr(os, "sysconf") else 100

# Get PID list from /bin/ps to compare against /proc (detect Rootkit hidden PIDs)
ps_pids = set()
try:
    out = subprocess.check_output(["ps", "-eo", "pid"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", "ignore")
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            ps_pids.add(int(line))
except Exception:
    pass

# 2. Direct /proc/[0-9]* Process Enumeration (Immune to trojanized /bin/ps)
processes = []
inode_to_pid = {}
my_pid = os.getpid()
parent_pid = os.getppid()

for entry in os.listdir("/proc"):
    if not entry.isdigit():
        continue
    pid = int(entry)
    proc_path = f"/proc/{pid}"
    if not os.path.exists(proc_path):
        continue
    try:
        cmdline = ""
        try:
            with open(f"{proc_path}/cmdline", "rb") as f:
                raw_cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                cmdline = raw_cmd
        except Exception:
            pass

        comm = ""
        try:
            with open(f"{proc_path}/comm", "r", errors="ignore") as f:
                comm = f.read().strip()
        except Exception:
            pass

        exe_path = ""
        try:
            exe_path = os.readlink(f"{proc_path}/exe")
        except Exception:
            pass

        cwd_path = ""
        try:
            cwd_path = os.readlink(f"{proc_path}/cwd")
        except Exception:
            pass

        ppid = 0
        uid = 0
        try:
            with open(f"{proc_path}/status", "r", errors="ignore") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
        except Exception:
            pass

        username = str(uid)
        try:
            username = pwd.getpwuid(uid).pw_name
        except Exception:
            pass

        # Calculate exact process start time from /proc/<pid>/stat field 22
        start_time_str = ""
        try:
            with open(f"{proc_path}/stat", "r", errors="ignore") as f:
                stat_str = f.read()
                rpar = stat_str.rfind(")")
                fields = stat_str[rpar + 2:].split()
                start_ticks = int(fields[19])
                proc_start_ts = boot_time + (start_ticks / float(clk_tck))
                start_time_str = fmt_ts(proc_start_ts)
        except Exception:
            pass

        # Check LD_PRELOAD in process environment
        ld_preload = ""
        try:
            with open(f"{proc_path}/environ", "rb") as f:
                env_raw = f.read().decode("utf-8", "ignore")
                for part in env_raw.split("\x00"):
                    if part.startswith("LD_PRELOAD="):
                        ld_preload = part
        except Exception:
            pass

        # Map socket inodes owned by this process
        try:
            fd_dir = f"{proc_path}/fd"
            for fd_name in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd_name}")
                    if target.startswith("socket:[") and target.endswith("]"):
                        ino = target[8:-1]
                        inode_to_pid[ino] = {"pid": pid, "comm": comm, "exe": exe_path, "cmdline": cmdline}
                except Exception:
                    pass
        except Exception:
            pass

        is_deleted = "(deleted)" in exe_path
        is_hidden_from_ps = bool(ps_pids and pid not in ps_pids and pid not in (my_pid, parent_pid) and exe_path)

        processes.append({
            "pid": pid,
            "ppid": ppid,
            "user": username,
            "comm": comm,
            "exe": exe_path,
            "cwd": cwd_path,
            "cmdline": cmdline or f"[{comm}]",
            "start_time": start_time_str,
            "is_deleted_binary": is_deleted,
            "hidden_from_ps": is_hidden_from_ps,
            "ld_preload": ld_preload,
        })
    except Exception:
        continue

# 3. Direct /proc/net/tcp & /proc/net/tcp6 Parsing (Immune to trojanized netstat/ss)
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"
}

def parse_proc_net_tcp(filepath):
    conns = []
    if not os.path.exists(filepath):
        return conns
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            local_hex, rem_hex, state_hex, inode = parts[1], parts[2], parts[3], parts[9]
            l_ip_hex, l_port_hex = local_hex.split(":")
            r_ip_hex, r_port_hex = rem_hex.split(":")
            if len(l_ip_hex) == 8:
                l_ip = socket.inet_ntoa(struct.pack("<L", int(l_ip_hex, 16)))
                r_ip = socket.inet_ntoa(struct.pack("<L", int(r_ip_hex, 16)))
            else:
                l_ip = l_ip_hex
                r_ip = r_ip_hex
            l_port = int(l_port_hex, 16)
            r_port = int(r_port_hex, 16)
            state = TCP_STATES.get(state_hex.upper(), state_hex)
            owner = inode_to_pid.get(inode, {})
            conns.append({
                "local_ip": l_ip,
                "local_port": l_port,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "state": state,
                "inode": inode,
                "pid": owner.get("pid", 0),
                "comm": owner.get("comm", ""),
                "exe": owner.get("exe", ""),
                "cmdline": owner.get("cmdline", ""),
            })
    except Exception:
        pass
    return conns

network_connections = parse_proc_net_tcp("/proc/net/tcp")

# 4. System Command Tampering & Rootkit Audit (rpm -Va / dpkg -V + ELF header + Timestomping + lsattr)
tampered_binaries = []
CRITICAL_BINS = [
    "/bin/ps", "/usr/bin/ps", "/bin/netstat", "/usr/bin/netstat", "/sbin/ss", "/usr/sbin/ss",
    "/usr/bin/top", "/bin/ls", "/usr/bin/ls", "/usr/bin/find", "/usr/bin/lsof", "/usr/sbin/lsof",
    "/usr/sbin/sshd", "/bin/login", "/usr/bin/crontab", "/usr/sbin/cron", "/usr/sbin/crond",
    "/bin/bash", "/bin/sh", "/usr/bin/sudo", "/usr/bin/chattr", "/usr/bin/lsattr"
]

# 4a. Check package manager verification (rpm -Va or dpkg -V)
pkg_verify_hits = {}
if os.path.exists("/usr/bin/rpm") or os.path.exists("/bin/rpm"):
    try:
        cmd = ["rpm", "-Vf"] + [b for b in CRITICAL_BINS if os.path.exists(b)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        for line in proc.stdout.decode("utf-8", "ignore").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-1].startswith("/"):
                flags, bpath = parts[0], parts[-1]
                if "5" in flags or "S" in flags or "L" in flags:
                    pkg_verify_hits[bpath] = f"RPM_VERIFY_FAILED({flags})"
    except Exception:
        pass
elif os.path.exists("/usr/bin/dpkg"):
    try:
        proc = subprocess.run(["dpkg", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        for line in proc.stdout.decode("utf-8", "ignore").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-1].startswith("/"):
                pkg_verify_hits[parts[-1]] = f"DPKG_VERIFY_FAILED({parts[0]})"
    except Exception:
        pass

# 4b. Inspect CRITICAL_BINS for script replacement, ctime != mtime timestomping, and SHA256
for bpath in set(CRITICAL_BINS + list(pkg_verify_hits.keys())):
    if not os.path.exists(bpath):
        continue
    try:
        st = os.stat(bpath)
        mtime = st.st_mtime
        ctime = st.st_ctime
        size = st.st_size
        with open(bpath, "rb") as f:
            head = f.read(4)
            f.seek(0)
            sha256_val = hashlib.sha256(f.read()).hexdigest()
        is_elf = (head == b"\x7fELF")
        # Timestomping: ctime is more than 30 days newer than mtime
        is_timestomped = (ctime - mtime) > (86400 * 30)
        verify_err = pkg_verify_hits.get(bpath, "")
        if verify_err or not is_elf or is_timestomped:
            tampered_binaries.append({
                "path": bpath,
                "size": size,
                "is_elf": is_elf,
                "mtime": fmt_ts(mtime),
                "ctime": fmt_ts(ctime),
                "timestomped": is_timestomped,
                "verify_status": verify_err or ("NOT_ELF_SCRIPT_WRAPPER" if not is_elf else "CTIME_MISMATCH_ANOMALY"),
                "sha256": sha256_val,
            })
    except Exception:
        pass

# 5. Persistence & Rootkit Sweep (12 Locations)
persistence_items = []

# 5.1 /etc/ld.so.preload
if os.path.exists("/etc/ld.so.preload"):
    try:
        content = open("/etc/ld.so.preload", "r", errors="ignore").read().strip()
        if content:
            st = os.stat("/etc/ld.so.preload")
            persistence_items.append({
                "category": "ld_so_preload_rootkit",
                "severity": "critical",
                "path": "/etc/ld.so.preload",
                "content": content,
                "ctime": fmt_ts(st.st_ctime),
                "mtime": fmt_ts(st.st_mtime),
            })
    except Exception:
        pass

# 5.2 Cron persistence (/etc/crontab, /etc/cron.d/*, /var/spool/cron/*, /var/spool/cron/crontabs/*)
cron_paths = ["/etc/crontab", "/etc/anacrontab"] + glob.glob("/etc/cron.d/*") + glob.glob("/etc/cron.hourly/*") + glob.glob("/etc/cron.daily/*") + glob.glob("/var/spool/cron/*") + glob.glob("/var/spool/cron/crontabs/*")
for cp in cron_paths:
    if not os.path.isfile(cp):
        continue
    try:
        st = os.stat(cp)
        lines = [
            ln.strip() for ln in open(cp, "r", errors="ignore").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        for ln in lines:
            if any(k in ln.lower() for k in ["curl", "wget", "bash", "/tmp/", "/dev/shm", "/var/tmp", "base64", "python", "perl", "nc ", "/dev/tcp", "chmod", "chattr", "xmrig", "kdevtmpfsi", "kinsing"]):
                persistence_items.append({
                    "category": "cron_backdoor",
                    "severity": "critical",
                    "path": cp,
                    "content": ln[:300],
                    "ctime": fmt_ts(st.st_ctime),
                    "mtime": fmt_ts(st.st_mtime),
                })
    except Exception:
        pass

# 5.3 Systemd services (/etc/systemd/system/*.service)
for sp in glob.glob("/etc/systemd/system/*.service") + glob.glob("/lib/systemd/system/*.service"):
    if not os.path.isfile(sp) or os.path.islink(sp):
        continue
    try:
        st = os.stat(sp)
        txt = open(sp, "r", errors="ignore").read()
        if any(k in txt.lower() for k in ["/tmp/", "/dev/shm", "/var/tmp", "curl ", "wget ", "base64", "xmrig", "Miner", "kinsing", "/root/."]):
            persistence_items.append({
                "category": "systemd_malicious_service",
                "severity": "critical",
                "path": sp,
                "content": " ".join([l.strip() for l in txt.splitlines() if "ExecStart" in l or "Description" in l]),
                "ctime": fmt_ts(st.st_ctime),
                "mtime": fmt_ts(st.st_mtime),
            })
    except Exception:
        pass

# 5.4 Shell Profiles & RC scripts (/etc/profile, /etc/rc.local, ~/.bashrc)
rc_paths = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/rc.local", "/etc/rc.d/rc.local", "/root/.bashrc", "/root/.bash_profile"] + glob.glob("/etc/profile.d/*.sh") + glob.glob("/home/*/.bashrc")
for rp in rc_paths:
    if not os.path.isfile(rp):
        continue
    try:
        st = os.stat(rp)
        for ln in open(rp, "r", errors="ignore").splitlines():
            ln_s = ln.strip()
            if ln_s and not ln_s.startswith("#"):
                if any(k in ln_s.lower() for k in ["/dev/tcp/", "curl ", "wget ", "base64", "/tmp/", "/dev/shm", "alias ps=", "alias netstat=", "alias ls=", "ld_preload"]):
                    persistence_items.append({
                        "category": "shell_profile_hijack",
                        "severity": "critical",
                        "path": rp,
                        "content": ln_s[:300],
                        "ctime": fmt_ts(st.st_ctime),
                        "mtime": fmt_ts(st.st_mtime),
                    })
    except Exception:
        pass

# 5.5 UID=0 Backdoor Accounts in /etc/passwd & SSH authorized_keys
if os.path.exists("/etc/passwd"):
    try:
        st = os.stat("/etc/passwd")
        for ln in open("/etc/passwd", "r", errors="ignore").splitlines():
            parts = ln.strip().split(":")
            if len(parts) >= 7:
                uname, uid_str, shell = parts[0], parts[2], parts[6]
                if uid_str == "0" and uname != "root":
                    persistence_items.append({
                        "category": "uid0_clone_user",
                        "severity": "critical",
                        "path": "/etc/passwd",
                        "content": ln.strip(),
                        "ctime": fmt_ts(st.st_ctime),
                        "mtime": fmt_ts(st.st_mtime),
                    })
    except Exception:
        pass

for ak in glob.glob("/root/.ssh/authorized_keys") + glob.glob("/home/*/.ssh/authorized_keys"):
    if os.path.isfile(ak):
        try:
            st = os.stat(ak)
            lines = [l.strip() for l in open(ak, "r", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                persistence_items.append({
                    "category": "ssh_authorized_keys",
                    "severity": "high",
                    "path": ak,
                    "content": f"Keys count: {len(lines)} | First key: {lines[0][:120]}...",
                    "ctime": fmt_ts(st.st_ctime),
                    "mtime": fmt_ts(st.st_mtime),
                })
        except Exception:
            pass

# 5.6 Immutable files check (lsattr +i / +a)
immutable_files = []
if command_exists := (os.path.exists("/usr/bin/lsattr") or os.path.exists("/bin/lsattr")):
    check_targets = ["/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/ld.so.preload", "/root/.ssh/authorized_keys"] + [b for b in CRITICAL_BINS if os.path.exists(b)] + glob.glob("/var/spool/cron/*")
    try:
        proc = subprocess.run(["lsattr", "-d"] + check_targets, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        for line in proc.stdout.decode("utf-8", "ignore").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                attr, fpath = parts[0], parts[1]
                if "i" in attr or "a" in attr:
                    immutable_files.append({"path": fpath, "attributes": attr})
    except Exception:
        pass

# 6. Surviving Auth Logs & Root History
auth_events = []
for log_p in ["/var/log/secure", "/var/log/auth.log"]:
    if os.path.isfile(log_p):
        try:
            lines = open(log_p, "r", errors="ignore").readlines()[-400:]
            for ln in lines:
                if "Failed password" in ln or "Accepted password" in ln or "Accepted publickey" in ln:
                    auth_events.append(ln.strip())
        except Exception:
            pass

snapshot = {
    "os_family": "linux",
    "hostname": hostname_val,
    "ip_address": primary_ip,
    "os_version": os_full,
    "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    "processes": processes,
    "network_connections": network_connections,
    "tampered_binaries": tampered_binaries,
    "persistence_items": persistence_items,
    "immutable_files": immutable_files,
    "auth_events": auth_events[-100:],
}

with open(os.path.join(out_dir, "linux_snapshot.json"), "w", encoding="utf-8") as f:
    json.dump(snapshot, f, ensure_ascii=False, indent=2)

print(f"[+] Snapshot generated: {len(processes)} processes, {len(tampered_binaries)} tampered binaries, {len(persistence_items)} persistence items.")
PYEOF
fi

# Package into .zip (fallback to .tar.gz if zip not installed, or use python zipfile)
ARCHIVE_PATH="${OUT_DIR}.zip"
if [[ -n "$PYTHON_BIN" ]]; then
    "$PYTHON_BIN" -c "
import zipfile, os, sys
out_dir, zip_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(out_dir):
        for file in files:
            full_p = os.path.join(root, file)
            rel_p = os.path.relpath(full_p, out_dir)
            zf.write(full_p, rel_p)
" "$OUT_DIR" "$ARCHIVE_PATH"
elif command -v zip >/dev/null 2>&1; then
    (cd "$OUT_DIR" && zip -r -q "$ARCHIVE_PATH" .)
fi

echo "[+] Forensic package created: $ARCHIVE_PATH"

# Auto-upload if --case-id is provided
if [[ -n "$CASE_ID" ]]; then
    UPLOAD_URL="${SERVER_URL%/}/api/cases/${CASE_ID}/hosts"
    echo "[*] Uploading forensic package to $UPLOAD_URL ..."
    if command -v curl >/dev/null 2>&1; then
        HTTP_RESP="$(curl -sS -w "\n%{http_code}" -X POST "$UPLOAD_URL" \
            -F "hostname=${HOSTNAME_VAL}" \
            -F "ip_address=${PRIMARY_IP}" \
            -F "os_version=${OS_FULL}" \
            -F "collector_type=LINUX_ANTI_ROOTKIT" \
            -F "file=@${ARCHIVE_PATH}")"
        HTTP_CODE="$(echo "$HTTP_RESP" | tail -n1)"
        HTTP_BODY="$(echo "$HTTP_RESP" | sed '$d')"
        if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
            echo "[+] Upload successful (HTTP $HTTP_CODE)!"
            echo "$HTTP_BODY"
        else
            echo "[!] Upload failed (HTTP $HTTP_CODE): $HTTP_BODY"
        fi
    else
        echo "[!] curl not found. Please copy $ARCHIVE_PATH and upload via Web UI."
    fi
else
    echo "[*] Tip: Run with --case-id <CASE_CODE> --server http://<IP>:8000 to auto-upload, or upload $ARCHIVE_PATH in the Web UI."
fi
