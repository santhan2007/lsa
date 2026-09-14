"""
Process Monitor Scanner — deep Linux process inventory.

Classifies EVERY process on the system, including kernel threads:
  KERNEL — kernel threads (descendants of kthreadd, pid 2)
  SYSTEM — OS services & daemons (system users, uid < 1000)
  USER   — user-launched applications (uid >= 1000)
"""

import os
import time
from datetime import datetime

import psutil


KERNEL_ROOT_PID = 2  # kthreadd — parent of all kernel threads on Linux

# Well-known system daemon accounts (fallback when uid >= 1000 on exotic distros)
SYSTEM_USERS = {
    "root", "daemon", "bin", "sys", "lp", "mail", "news", "uucp", "man",
    "nobody", "systemd-network", "systemd-resolve", "systemd-timesync",
    "dbus", "messagebus", "sshd", "avahi", "avahi-autoipd", "rtkit",
    "polkitd", "colord", "cups", "pulse", "postfix", "www-data", "nginx",
    "apache", "mysql", "postgres", "redis", "dnsmasq", "chrony", "ntp",
    "tss", "geoclue", "usbmuxd", "nm-openvpn", "nm-openconnect", "sddm",
    "gdm", "lightdm",
}


def _descendants_of(root_pid, parent_of):
    """Return all descendant PIDs of root_pid given a {ppid: [child pids]} map."""
    seen = set()
    stack = [root_pid]
    while stack:
        pid = stack.pop()
        for child in parent_of.get(pid, ()):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


def run() -> dict:
    """Collect a complete process inventory including kernel threads"""
    try:
        # ---- Pass 1: prime CPU counters, cache identities, build parent map ----
        procs = []
        parent_of = {}
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'uids', 'status']):
            try:
                proc.cpu_percent(None)  # prime the CPU counter
                procs.append(proc)
                parent_of.setdefault(proc.info['ppid'], []).append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        kernel_pids = _descendants_of(KERNEL_ROOT_PID, parent_of)

        # Short window so primed CPU counters produce a meaningful delta
        time.sleep(0.2)

        # ---- Pass 2: collect the full inventory ----
        rows = []
        for proc in procs:
            try:
                with proc.oneshot():
                    info = proc.info
                    pid = info['pid']
                    name = info['name'] or f"(pid {pid})"
                    ppid = info['ppid']
                    username = info['username']
                    uids = info.get('uids')
                    real_uid = uids.real if uids else None
                    status = (info['status'] or 'unknown').lower()
                    cpu = proc.cpu_percent(None)
                    mem_percent = proc.memory_percent()

                    try:
                        rss_mb = round((proc.memory_info().rss or 0) / (1024 * 1024), 2)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        rss_mb = 0.0
                    try:
                        threads = proc.num_threads()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        threads = 0
                    try:
                        cmdline_parts = proc.cmdline()
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        cmdline_parts = []
                    try:
                        started = datetime.fromtimestamp(proc.create_time()).strftime("%b %d %H:%M")
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, OverflowError):
                        started = ""

                # --- Classification: KERNEL > SYSTEM > USER ---
                if pid == KERNEL_ROOT_PID or pid in kernel_pids:
                    kind = "KERNEL"
                elif (real_uid is not None and real_uid < 1000) or (username in SYSTEM_USERS):
                    kind = "SYSTEM"
                else:
                    kind = "USER"

                rows.append({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "username": username or ("root" if real_uid == 0 else "—"),
                    "uid": real_uid,
                    "kind": kind,
                    "state": status,
                    "cpu_percent": round(cpu, 2),
                    "memory_percent": round(mem_percent or 0.0, 2),
                    "rss_mb": rss_mb,
                    "threads": threads,
                    "cmdline": " ".join(cmdline_parts)[:200] if cmdline_parts else "",
                    "started": started,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # ---- Aggregates ----
        total = len(rows)
        kernel_rows = [r for r in rows if r["kind"] == "KERNEL"]
        system_rows = [r for r in rows if r["kind"] == "SYSTEM"]
        user_rows = [r for r in rows if r["kind"] == "USER"]
        zombies = [r for r in rows if r["state"] == "zombie"]
        privileged = [r for r in rows if r["uid"] == 0 and r["kind"] != "KERNEL"]

        high_cpu = sorted(
            [r for r in rows if r["cpu_percent"] > 10],
            key=lambda r: r["cpu_percent"], reverse=True)
        high_mem = sorted(
            [r for r in rows if r["memory_percent"] > 5],
            key=lambda r: r["memory_percent"], reverse=True)
        top_cpu = sorted(rows, key=lambda r: r["cpu_percent"], reverse=True)[:10]
        top_mem = sorted(rows, key=lambda r: r["rss_mb"], reverse=True)[:10]

        network_keywords = ['ssh', 'http', 'nginx', 'apache', 'mysql', 'postgres',
                            'mongo', 'redis', 'ftp', 'docker', 'containerd']
        network_related = [r for r in rows
                           if any(k in r["name"].lower() for k in network_keywords)]

        try:
            load1, load5, load15 = os.getloadavg()
        except (OSError, AttributeError):
            load1 = load5 = load15 = 0.0

        details = {
            "total_processes": total,
            "kernel_threads": len(kernel_rows),
            "system_services": len(system_rows),
            "user_processes": len(user_rows),
            "privileged_processes": len(privileged),
            "zombie_processes": len(zombies),
            "network_related_processes": len(network_related),
            "high_cpu_processes": high_cpu[:10],
            "high_memory_processes": high_mem[:10],
            "top_cpu_consumers": top_cpu,
            "top_memory_consumers": top_mem,
            "total_rss_mb": round(sum(r["rss_mb"] for r in rows), 1),
            "load_average": {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)},
            "cpu_count": psutil.cpu_count(),
            # Full inventory — sorted by memory so the heaviest are first
            "processes": sorted(rows, key=lambda r: (-r["rss_mb"], r["pid"])),
        }

        if zombies:
            summary = (f"{total} processes ({len(kernel_rows)} kernel threads, "
                       f"{len(system_rows)} system services, {len(user_rows)} user apps) — "
                       f"{len(zombies)} zombie process(es) detected!")
        else:
            summary = (f"{total} processes: {len(kernel_rows)} kernel threads, "
                       f"{len(system_rows)} system services, {len(user_rows)} user apps.")

        base = {
            "name": "Process Monitor",
            "status": "INFO",
            "score": 10,
            "max_score": 10,
            "summary": summary,
            "details": details,
            "recommendation": ("Kernel threads (purple) are normal and always present. "
                               "Be suspicious of user-space processes that mimic kernel "
                               "thread names in [brackets] — rootkits use this trick to hide."),
            "why_it_matters": ("A complete inventory — including kernel threads and system "
                               "daemons — is the only way to spot hidden or disguised "
                               "processes consuming your resources."),
            "evidence": [],
        }
        from .common import format_check
        return format_check(base, scanner_id="processes", category="PROCESSES")

    except Exception as e:
        base = {
            "name": "Process Monitor",
            "status": "UNKNOWN",
            "score": 0,
            "max_score": 10,
            "summary": f"Error checking processes: {str(e)}",
            "details": {},
            "recommendation": "Check system permissions and try again.",
            "why_it_matters": "",
            "evidence": [],
        }
        from .common import format_check
        return format_check(base, scanner_id="processes", category="PROCESSES")
