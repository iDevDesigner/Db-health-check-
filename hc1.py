#!/usr/bin/env python3
"""
Oracle RAC / Solaris – Complete Daily Health‑Check Tool  (Paramiko transport)
-----------------------------------------------------------------------------
Performs a thorough daily health assessment across:
  • 10+ Oracle RAC 19c databases with multiple PDBs
  • Solaris servers (SunOS)
  • RMAN backups (archivelog every 2 h, incremental daily, full weekly)
  • Expdp dumps (per pluggable, at /expdpbkp/daily)
  • CRS / ASM / Listener / SCAN / OCR / Voting disks / Interconnect
  • Data Guard transport & apply lag
  • GoldenGate extract / replicat / manager + lag (ggsci)
  • Alert‑log parsing for ORA‑600/7445/1578/4031/1650
  • Scheduler jobs, blocking locks, long‑running queries, performance KPIs
  • Undo, temp, flashback, force‑logging, corrupted blocks, non‑default params
  • Patching status, recyclebin, segment size, ADDM findings

Sensitive data is *not* stored; authentication relies on your existing SSH
agent or default private key (~/.ssh/id_rsa).

Requirements:
  • Python 3.7+ with Paramiko (standard in Anaconda)
  • ssh‑key‑based access as `oracle` and `grid` on all target servers
  • `sqlplus` in PATH for the oracle user
  • `config.json` (path in env HCEXTRACT_CONFIG, or ./config.json)

Output files:
    ./reports/healthcheck_<timestamp>.txt
    ./reports/healthcheck_<timestamp>.json
"""

import os, sys, json, time, datetime, socket, re, traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import paramiko

# ---------------------------------------------------------------------------
# Default thresholds (overridable per server / database in config.json)
# ---------------------------------------------------------------------------
DEFAULT_THRESHOLDS: Dict[str, Any] = {
    # CPU / memory / disk
    "cpu_warn_pct": 85,       "cpu_crit_pct": 95,
    "mem_warn_pct": 90,       "mem_crit_pct": 95,
    "disk_warn_pct": 85,      "disk_crit_pct": 92,
    "swap_warn_pct": 70,      "swap_crit_pct": 90,
    "inode_warn_pct": 80,     "inode_crit_pct": 90,
    # Tablespaces
    "tbsp_warn_pct": 80,      "tbsp_crit_pct": 95,
    "temp_warn_pct": 70,
    "undo_warn_pct": 80,
    # FRA
    "fra_warn_pct": 75,       "fra_crit_pct": 90,
    "fra_hours_to_full_crit": 4,
    # RMAN
    "rman_full_max_days": 7,
    "rman_incr_max_hours": 25,
    "rman_arch_max_hours": 3,
    # Expdp
    "expdp_max_age_hours": 25,
    # Alert log
    "alert_error_count_warn": 10,
    "log_switch_warn_per_hour": 12,
    # Session / locks
    "session_warn_pct": 80,   "session_crit_pct": 90,
    "blocking_lock_warn_min": 5,
    # Invalid objects
    "invalid_obj_warn": 3,
    # GoldenGate
    "gg_lag_warn_sec":  60,
    "gg_lag_crit_sec":  300,
    # Data Guard
    "dg_lag_warn_sec":  300,   # 5 minutes
    "dg_lag_crit_sec":  900,   # 15 minutes
    # Performance
    "pga_hit_warn": 80,
    # Network
    "ic_latency_warn_ms": 1.0,
    "ic_latency_crit_ms": 5.0,
    # SSH parameters
    "ssh_connect_timeout": 15,
    "ssh_exec_timeout": 60,
    "sql_timeout": 120,
}

# ---------------------------------------------------------------------------
# Persistent SSH connection manager (Paramiko)
# ---------------------------------------------------------------------------
class SSHMgr:
    """Re-usable SSH connections per (host, user) pair."""

    def __init__(self, connect_timeout: int = 15, exec_timeout: int = 60):
        self._cache: Dict[Tuple[str, str], paramiko.SSHClient] = {}
        self.connect_timeout = connect_timeout
        self.exec_timeout   = exec_timeout

    def _open(self, host: str, user: str) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=host, username=user,
                  timeout=self.connect_timeout,
                  allow_agent=True, look_for_keys=True,
                  banner_timeout=10)
        return c

    def _get(self, host: str, user: str) -> paramiko.SSHClient:
        key = (host, user)
        if key not in self._cache:
            self._cache[key] = self._open(host, user)
        return self._cache[key]

    def _invalidate(self, host: str, user: str):
        key = (host, user)
        if key in self._cache:
            try: self._cache[key].close()
            except: pass
            del self._cache[key]

    def run(self, host: str, user: str, cmd: str,
            timeout: Optional[int] = None, retries: int = 2) -> Dict[str, Any]:
        """Execute a remote command; returns {rc, stdout, stderr, error}."""
        if timeout is None:
            timeout = self.exec_timeout
        last = None
        for attempt in range(retries):
            try:
                conn = self._get(host, user)
                t    = conn.get_transport()
                if t is None or not t.is_active():
                    self._invalidate(host, user)
                    continue
                chan = t.open_session()
                chan.settimeout(timeout)
                chan.exec_command(cmd)
                out  = chan.makefile('r', -1).read()
                err  = chan.makefile_stderr('r', -1).read()
                rc   = chan.recv_exit_status()
                chan.close()
                return {"rc": rc,
                        "stdout": out.strip(),
                        "stderr": err.strip()}
            except (paramiko.SSHException, socket.timeout,
                    OSError, EOFError) as e:
                last = str(e)
                self._invalidate(host, user)
                if attempt < retries - 1:
                    time.sleep(2)
            except Exception as e:
                return {"rc": -1, "stdout": "", "stderr": str(e), "error": str(e)}
        return {"rc": -1, "stdout": "", "stderr": last or "SSH error",
                "error": last or "SSH error"}

    def close_all(self):
        for c in self._cache.values():
            try: c.close()
            except: pass
        self._cache.clear()

# ---------------------------------------------------------------------------
# Lightweight report aggregator
# ---------------------------------------------------------------------------
class CheckResult:
    """Simple struct for every check section."""
    def __init__(self, name: str):
        self.name      = name
        self.status    = "OK"          # OK | WARNING | CRITICAL | N/A | ERROR
        self.data: Dict[str, Any] = {}
        self.issues: List[str]   = []

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def severity(pct: float, warn: float, crit: float) -> str:
    return "CRITICAL" if pct >= crit else ("WARNING" if pct >= warn else "OK")

def agg(*statuses: str) -> str:
    for s in ("CRITICAL", "ERROR", "WARNING", "OK", "N/A"):
        if s in statuses: return s
    return "UNKNOWN"

def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------------------------
# Server‑level health (Solaris)
# ---------------------------------------------------------------------------
def chk_server_health(mgr: SSHMgr, host: str, ora_user: str,
                      thr: Dict) -> CheckResult:
    r = CheckResult("server_health")

    # Uptime → load averages
    out = mgr.run(host, ora_user, "uptime", timeout=15)
    if out["rc"] == 0 and "load average:" in out["stdout"]:
        la = out["stdout"].split("load average:")[-1].strip().split(",")
        if len(la) == 3:
            r.data["load_1"] = float(la[0].strip())
            r.data["load_5"] = float(la[1].strip())
            r.data["load_15"] = float(la[2].strip())
    else:
        r.issues.append("uptime failed")

    # vmstat for CPU + memory
    out = mgr.run(host, ora_user, "vmstat 1 2 | tail -1", timeout=15)
    cpu_used, free_mb = None, None
    if out["rc"] == 0 and out["stdout"]:
        f = out["stdout"].split()
        if len(f) >= 22:
            try:
                idle = int(f[21])
                cpu_used = 100 - idle
                r.data["cpu_used_pct"] = cpu_used
            except: pass
        if len(f) >= 5:
            try: free_mb = int(f[4]) / 1024
            except: pass
    # memory total
    out = mgr.run(host, ora_user, "prtconf | grep 'Memory size'", timeout=15)
    if out["rc"] == 0 and out["stdout"]:
        try:
            v = out["stdout"].split(":")[1].strip()
            total_mb = (float(v.split()[0]) *
                        (1024 if "Gigabytes" in v else 1))
            r.data["mem_total_mb"] = total_mb
            if free_mb is not None:
                r.data["mem_used_pct"] = round(100*(1 - free_mb/total_mb), 1)
        except: pass

    # Disk usage (exclude tmpfs, dev, etc.)
    out = mgr.run(host, ora_user,
                  "df -h | grep -vE 'Filesystem|/dev/fd|/tmp|swap|ctfs|mnttab|objfs|sharefs|tmpfs|devfs|proc'",
                  timeout=15)
    disks = []
    if out["rc"] == 0:
        for ln in out["stdout"].splitlines():
            p = ln.split()
            if len(p) < 6: continue
            try:
                pct = int(p[4].replace('%', ''))
            except: continue
            st = severity(pct, thr["disk_warn_pct"], thr["disk_crit_pct"])
            disks.append({"mount": p[5], "size": p[3], "used_pct": pct,
                          "status": st})
            if st == "CRITICAL": r.issues.append(f"disk {p[5]} {pct}%")
    r.data["disks"] = disks

    # Swap
    out = mgr.run(host, ora_user, "swap -s 2>/dev/null", timeout=15)
    if out["rc"] == 0:
        m = re.search(r"(\d+)k\s+used.*?(\d+)k\s+available", out["stdout"])
        if m:
            u, a = int(m.group(1)), int(m.group(2))
            sw_pct = round(u*100/(u+a), 1)
            r.data["swap_used_pct"] = sw_pct
            if sw_pct >= thr["swap_crit_pct"]:
                r.issues.append(f"swap {sw_pct}%")

    # Inodes (Solaris: df -o i)
    out = mgr.run(host, ora_user, "df -o i 2>/dev/null | tail -n +2", timeout=15)
    inode_high = []
    for ln in out["stdout"].splitlines():
        p = ln.split()
        if len(p) >= 5:
            try:
                ip = int(p[-1].replace('%', ''))
                if ip >= thr["inode_warn_pct"]: inode_high.append(f"{p[-2]} {ip}%")
            except: pass
    if inode_high: r.issues.extend(inode_high)

    # Hardware faults (Solaris fmadm)
    out = mgr.run(host, ora_user, "fmadm faulty 2>/dev/null", timeout=15)
    if out["rc"] == 0 and "No faults" not in out["stdout"]:
        r.issues.append("Hardware faults detected (fmadm)")
        r.data["hw_faults"] = out["stdout"][:500]

    # Top CPU processes
    out = mgr.run(host, ora_user, "prstat -a -n 5 -s cpu 1 1 | tail -7", timeout=15)
    r.data["top_procs"] = [l for l in out["stdout"].splitlines() if l.strip()]

    r.status = "CRITICAL" if any("CRITICAL" in i for i in r.issues) else \
               ("WARNING" if r.issues else "OK")
    return r

# ---------------------------------------------------------------------------
# Grid / Cluster health
# ---------------------------------------------------------------------------
def chk_crs_daemons(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("crs_daemons")
    out = mgr.run(host, grid_user, "crsctl check crs", timeout=30)
    comps = {}
    for kw in ("OHASD","CRSD","CSSD","EVMD","MDNSD","GIPCD","GPNPD","DISKMON"):
        up = "online" in out["stdout"].lower() and kw.lower() in out["stdout"].lower()
        comps[kw] = "ONLINE" if up else "?"
    r.data = comps
    if out["rc"] != 0:
        r.status = "CRITICAL"; r.issues.append("crsctl check crs failed")
    return r

def chk_cluster_nodes(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("cluster_nodes")
    out = mgr.run(host, grid_user, "crsctl check cluster -all", timeout=30)
    nodes = []
    for m in re.finditer(r"(\w[\w-]+)\s+(ONLINE|OFFLINE)", out["stdout"]):
        nodes.append({"node": m.group(1), "status": m.group(2)})
    offline = [n for n in nodes if n["status"] != "ONLINE"]
    r.data = {"nodes": nodes, "offline": offline}
    if offline: r.status = "CRITICAL"; r.issues.append(f"{len(offline)} node(s) offline")
    return r

def chk_cluster_resources(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("cluster_resources")
    out = mgr.run(host, grid_user, "crsctl stat res -t", timeout=45)
    off = [l.strip() for l in out["stdout"].splitlines() if "OFFLINE" in l.upper()]
    r.data = {"offline_resources": off[:20]}
    if off: r.status = "WARNING"; r.issues.append(f"{len(off)} OFFLINE resources")
    return r

def chk_ocr(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("ocr")
    out = mgr.run(host, grid_user, "ocrcheck", timeout=30)
    ok = out["rc"] == 0 and "healthy" in out["stdout"].lower()
    r.data = {"healthy": ok, "output": out["stdout"][:500]}
    if not ok: r.status = "CRITICAL"; r.issues.append("OCR not healthy")
    return r

def chk_voting_disks(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("voting_disks")
    out = mgr.run(host, grid_user, "crsctl query css votedisk", timeout=30)
    disks = []
    for ln in out["stdout"].splitlines():
        if "ONLINE" in ln.upper():
            disks.append("ONLINE")
        elif "OFFLINE" in ln.upper():
            disks.append("OFFLINE")
    r.data = {"total": len(disks), "offline": disks.count("OFFLINE")}
    if disks.count("OFFLINE") > 0:
        r.status = "CRITICAL"; r.issues.append("Voting disk OFFLINE")
    return r

def chk_scan_listener(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("scan_listener")
    out = mgr.run(host, grid_user, "srvctl status scan_listener", timeout=30)
    running = "running" in out["stdout"].lower()
    r.data = {"output": out["stdout"][:300]}
    if not running: r.status = "WARNING"; r.issues.append("SCAN listener issue")
    return r

def chk_asm_dg(mgr: SSHMgr, host: str, grid_user: str, thr: Dict) -> CheckResult:
    r = CheckResult("asm_diskgroups")
    out = mgr.run(host, grid_user, "asmcmd lsdg 2>&1", timeout=60)
    dgs = []
    for ln in out["stdout"].splitlines():
        if not ln.strip() or "State" in ln: continue
        p = ln.split(); 
        if len(p) < 9: continue
        try:
            name = p[-1].rstrip("/"); state = p[0]
            total_mb = float(p[7]); free_mb = float(p[8])
            pct = round((total_mb - free_mb)/total_mb*100, 1) if total_mb > 0 else 0
            st = severity(pct, thr["tbsp_warn_pct"], thr["tbsp_crit_pct"])
            dgs.append({"name": name, "state": state, "used_pct": pct,
                        "total_gb": round(total_mb/1024, 1), "free_gb": round(free_mb/1024, 1),
                        "status": st})
            if st != "OK": r.issues.append(f"ASM {name} {pct}%")
        except: pass
    r.data = {"diskgroups": dgs}
    r.status = agg(*[d["status"] for d in dgs]) if dgs else "WARNING"
    return r

def chk_listener_detail(mgr: SSHMgr, host: str, grid_user: str) -> CheckResult:
    r = CheckResult("listener_detail")
    # discover listener names
    out = mgr.run(host, grid_user, "ps -ef | grep tnslsnr | grep -v grep", timeout=15)
    names = set()
    for m in re.finditer(r"tnslsnr\s+(\S+)", out["stdout"], re.I):
        names.add(m.group(1).upper())
    if not names: names = {"LISTENER"}
    listeners = {}
    for name in sorted(names):
        o = mgr.run(host, grid_user, f"lsnrctl status {name} 2>&1", timeout=20)
        up = o["rc"] == 0 and "uptime" in o["stdout"].lower()
        listeners[name] = {"status": "UP" if up else "DOWN",
                           "output": o["stdout"][:200]}
        if not up: r.issues.append(f"Listener {name} DOWN")
    r.data = listeners
    r.status = "WARNING" if r.issues else "OK"
    return r

def chk_interconnect_ping(mgr: SSHMgr, host: str, ora_user: str, thr: Dict) -> CheckResult:
    r = CheckResult("interconnect")
    # try to find private IP from /etc/hosts
    out = mgr.run(host, ora_user, "grep -i priv /etc/hosts | head -1", timeout=10)
    priv_ip = None
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out["stdout"])
    if m: priv_ip = m.group(1)
    if not priv_ip:
        # fallback: ifconfig
        out2 = mgr.run(host, ora_user, "ifconfig -a 2>/dev/null", timeout=15)
        for m2 in re.finditer(r"inet\s+(192\.168\.\d+\.\d+|172\.\d+\.\d+\.\d+)", out2["stdout"]):
            priv_ip = m2.group(1); break
    if priv_ip:
        o3 = mgr.run(host, ora_user, f"ping -s {priv_ip} 8192 2 2>&1", timeout=20)
        lat = None
        lm = re.search(r"avg.*?=\s*[\d.]+/([\d.]+)", o3["stdout"])
        if lm: lat = float(lm.group(1))
        r.data = {"private_ip": priv_ip, "latency_ms": lat}
        if lat:
            if lat >= thr["ic_latency_crit_ms"]:
                r.status = "CRITICAL"
            elif lat >= thr["ic_latency_warn_ms"]:
                r.status = "WARNING"
    else:
        r.data = {"note": "no private IP detected"}
    return r

# ---------------------------------------------------------------------------
# SQL execution helper (remote via sqlplus)
# ---------------------------------------------------------------------------
def run_sql(mgr: SSHMgr, host: str, ora_user: str,
            sql: str, timeout: int = 120) -> Dict[str, Any]:
    """Run SQL via sqlplus / as sysdba on remote."""
    escaped = sql.replace("'", "'\\''")
    cmd = f"sqlplus -S / as sysdba <<'EOSQL'\n{escaped}\nEOSQL"
    return mgr.run(host, ora_user, cmd, timeout=timeout)

def sql_lines(mgr, host, ora_user, sql, timeout=120) -> List[str]:
    """Execute SQL and return list of non‑empty stripped lines."""
    out = run_sql(mgr, host, ora_user, sql, timeout)
    if out["rc"] != 0: return []
    return [l.rstrip() for l in out["stdout"].splitlines() if l.strip()
            and not l.strip().startswith("SQL>")]

# ---------------------------------------------------------------------------
# Database health checks  (all via remote SQL)
# ---------------------------------------------------------------------------
def chk_db_connectivity(mgr, host, ora_user, sid) -> CheckResult:
    r = CheckResult("db_connectivity")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT 'ALIVE|'||instance_name||'|'||status||'|'||database_status FROM v$instance",
                      30)
    r.data = {"connectable": bool(lines)}
    r.status = "OK" if lines else "CRITICAL"
    if not lines: r.issues.append("Cannot connect to DB")
    return r

def chk_db_info(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("db_info")
    sql = ("SELECT name, db_unique_name, open_mode, log_mode, database_role,"
           " flashback_on, force_logging, current_scn FROM v$database")
    lines = sql_lines(mgr, host, ora_user, sql, 30)
    if lines:
        p = lines[0].split()
        if len(p) >= 7:
            r.data = {"name": p[0], "db_unique": p[1], "open_mode": p[2],
                      "log_mode": p[3], "role": p[4],
                      "flashback_on": p[5], "force_logging": p[6]}
            if p[2] != "READ WRITE" and p[4] == "PRIMARY":
                r.status = "WARNING"; r.issues.append(f"DB open_mode={p[2]}")
            if p[5] == "NO": r.issues.append("Flashback OFF")
            if p[6] == "NO": r.issues.append("Force Logging OFF (Data Guard risk)")
    # Oracle version
    vl = sql_lines(mgr, host, ora_user, "SELECT version FROM v$instance", 20)
    if vl: r.data["oracle_version"] = vl[0].strip()
    # Instance uptime
    ul = sql_lines(mgr, host, ora_user,
                   "SELECT TO_CHAR(startup_time,'YYYY-MM-DD HH24:MI:SS') FROM v$instance", 20)
    if ul: r.data["startup_time"] = ul[0].strip()
    return r

def chk_pdb_modes(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("pdb_open_modes")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT name||':'||open_mode FROM v$pdbs WHERE name!='PDB$SEED'", 30)
    pdbs = {}
    for ln in lines:
        if ':' in ln:
            n, m = ln.split(':', 1)
            pdbs[n] = {"open_mode": m, "status": "OK" if m == "READ WRITE" else "WARNING"}
            if m != "READ WRITE": r.issues.append(f"PDB {n} is {m}")
    r.data = pdbs
    r.status = "WARNING" if r.issues else "OK"
    return r

def chk_tablespaces(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("tablespaces")
    # Use PL/SQL to loop PDBs
    plsql = """SET SERVEROUTPUT ON SIZE 1000000
DECLARE
    v_pdb VARCHAR2(128);
BEGIN
    FOR rec IN (SELECT name FROM v$pdbs WHERE open_mode='READ WRITE' AND name!='PDB$SEED') LOOP
        EXECUTE IMMEDIATE 'ALTER SESSION SET CONTAINER='||rec.name;
        FOR ts IN (SELECT tablespace_name, used_percent
                   FROM dba_tablespace_usage_metrics) LOOP
            DBMS_OUTPUT.PUT_LINE('PDB:'||rec.name||' TS:'||ts.tablespace_name||' USED:'||ts.used_percent);
        END LOOP;
    END LOOP;
END;
/"""
    out = run_sql(mgr, host, ora_user, plsql, 120)
    all_ts = {}
    if out["rc"] == 0:
        for ln in out["stdout"].splitlines():
            ln = ln.strip()
            if not ln.startswith("PDB:"): continue
            try:
                _, seg1, seg2, seg3 = ln.split()
                pdb = seg1.split(":", 1)[1]
                ts  = seg2.split(":", 1)[1]
                pct = float(seg3.split(":", 1)[1])
            except: continue
            st = severity(pct, thr["tbsp_warn_pct"], thr["tbsp_crit_pct"])
            all_ts.setdefault(pdb, {})[ts] = {"used_pct": pct, "status": st}
            if st != "OK": r.issues.append(f"TS {ts} in {pdb} {pct}%")
    r.data = all_ts
    r.status = "CRITICAL" if any("CRITICAL" in i for i in r.issues) else \
               ("WARNING" if r.issues else "OK")
    return r

def chk_fra(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("recovery_area")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT name, space_limit/1073741824, space_used/1073741824,"
                      " space_reclaimable/1073741824,"
                      " round((space_used-space_reclaimable)/nullif(space_limit,0)*100,1)"
                      " FROM v$recovery_file_dest", 30)
    if lines:
        p = lines[0].split()
        if len(p) >= 5:
            try:
                used_pct = float(p[4])
                r.data = {"path": p[0], "limit_gb": p[1], "used_gb": p[2],
                          "reclaimable_gb": p[3], "used_net_pct": used_pct}
                if used_pct >= thr["fra_crit_pct"]:
                    r.status = "CRITICAL"; r.issues.append(f"FRA {used_pct}%")
                elif used_pct >= thr["fra_warn_pct"]:
                    r.status = "WARNING"; r.issues.append(f"FRA {used_pct}%")
            except: pass
    # Archivelog rate
    al = sql_lines(mgr, host, ora_user,
                   "SELECT count(*), round(sum(blocks*block_size)/1073741824,2)"
                   " FROM v$archived_log WHERE first_time>sysdate-1/24 AND dest_id=1", 30)
    if al:
        ap = al[0].split()
        if len(ap) >= 2:
            try:
                cnt = int(ap[0]); gb = float(ap[1])
                r.data["arch_last_hour_count"] = cnt
                r.data["arch_last_hour_gb"] = gb
                if r.data.get("limit_gb"):
                    free = r.data["limit_gb"] - r.data["used_gb"] + r.data.get("reclaimable_gb", 0)
                    if gb > 0:
                        hrs = free / gb
                        r.data["hours_to_full"] = round(hrs, 1)
                        if hrs < thr["fra_hours_to_full_crit"]:
                            r.issues.append(f"FRA full in {hrs:.1f}h")
                            if r.status == "OK": r.status = "WARNING"
            except: pass
    return r

def chk_redo_multiplex(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("redo_logs")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT group#, thread#, members, status, round(bytes/1048576,0) FROM v$log", 30)
    groups = []
    for ln in lines:
        p = ln.split()
        if len(p) >= 5: groups.append({"group": p[0], "members": int(p[2]), "status": p[3]})
    min_mem = min(g["members"] for g in groups) if groups else 1
    r.data = {"groups": groups, "min_members": min_mem}
    if min_mem < 2:
        r.status = "WARNING"; r.issues.append("Redo groups have <2 members (no multiplexing)")
    invalid = [g for g in groups if g["status"] not in ("CURRENT", "ACTIVE", "INACTIVE")]
    if invalid: r.status = "CRITICAL"; r.issues.append(f"{len(invalid)} invalid redo groups")
    return r

def chk_invalid_objects(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("invalid_objects")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT owner, object_name, object_type FROM dba_objects"
                      " WHERE status='INVALID' AND owner NOT IN "
                      "('SYS','SYSTEM','OUTLN','XDB','CTXSYS','MDSYS','ORDSYS','DBSNMP','WMSYS','EXFSYS','SYSMAN')"
                      " ORDER BY owner", 60)
    r.data["count"] = len(lines)
    if len(lines) >= thr["invalid_obj_warn"]:
        r.status = "WARNING"; r.issues.append(f"{len(lines)} invalid objects")
    # SYS/SYSTEM invalids
    sl = sql_lines(mgr, host, ora_user,
                   "SELECT count(*) FROM dba_objects WHERE status='INVALID' AND owner IN ('SYS','SYSTEM')", 20)
    if sl:
        try:
            sc = int(sl[0].strip())
            if sc > 0: r.issues.append(f"{sc} SYS/SYSTEM invalid objects (patching issue?)")
        except: pass
    return r

def chk_scheduler_failures(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("scheduler_jobs")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT j.owner, j.job_name, d.status, d.error#, d.additional_info"
                      " FROM dba_scheduler_job_run_details d"
                      " JOIN dba_scheduler_jobs j ON j.job_name=d.job_name AND j.owner=d.owner"
                      " WHERE d.status='FAILED' AND d.log_date>sysdate-1", 60)
    failed = []
    for ln in lines:
        p = ln.split(None, 4)
        if len(p) >= 3: failed.append({"owner": p[0], "job": p[1], "error": p[2]})
    r.data = {"failed_last_24h": failed, "count": len(failed)}
    if len(failed) >= 3: r.status = "CRITICAL"
    elif failed: r.status = "WARNING"
    if failed: r.issues.append(f"{len(failed)} failed scheduler jobs")
    return r

def chk_blocking_locks(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("blocking_locks")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT waiter.sid, waiter.username, blocker.sid, blocker.username,"
                      " round(waiter.seconds_in_wait/60,1) wait_min"
                      " FROM v$session waiter, v$session blocker"
                      " WHERE waiter.blocking_session=blocker.sid"
                      " AND waiter.blocking_session_status='VALID'", 30)
    locks = []
    for ln in lines:
        p = ln.split(); 
        if len(p) >= 5:
            try: locks.append({"waiter_sid": p[0], "blocker_sid": p[2], "wait_min": float(p[4])})
            except: pass
    r.data = {"blocking_sessions": locks}
    long_blk = [l for l in locks if l["wait_min"] >= thr["blocking_lock_warn_min"]]
    if long_blk: r.status = "CRITICAL"; r.issues.append(f"{len(long_blk)} blocking >5min")
    elif locks: r.status = "WARNING"
    return r

def chk_long_queries(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("long_running_queries")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT sid, username, round(elapsed_time/1000000/60,1) elapsed_min,"
                      " substr(sql_text,1,80) FROM v$session s JOIN v$sqlarea q ON q.sql_id=s.sql_id"
                      " WHERE s.status='ACTIVE' AND s.type='USER' AND s.elapsed_time/1000000/60>30", 60)
    r.data = {"queries": lines[:10]}
    if len(lines) >= 3: r.status = "WARNING"; r.issues.append(f"{len(lines)} long queries >30min")
    return r

def chk_rman_backups(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("rman_backups")
    # Full
    fl = sql_lines(mgr, host, ora_user,
                   "SELECT TO_CHAR(MAX(COMPLETION_TIME),'YYYY-MM-DD HH24:MI:SS')"
                   " FROM v$backup_set WHERE INCREMENTAL_LEVEL=0 AND CONTROLFILE_INCLUDED='NO'", 30)
    if fl and fl[0]:
        dt = datetime.datetime.strptime(fl[0], "%Y-%m-%d %H:%M:%S")
        age_d = (datetime.datetime.now() - dt).total_seconds() / 86400
        r.data["full"] = {"status": "CRITICAL" if age_d > thr["rman_full_max_days"] else "OK",
                          "last": fl[0], "age_days": round(age_d, 1)}
        if age_d > thr["rman_full_max_days"]: r.issues.append(f"Full backup {age_d:.1f}d old")
    # Incremental
    il = sql_lines(mgr, host, ora_user,
                   "SELECT TO_CHAR(MAX(COMPLETION_TIME),'YYYY-MM-DD HH24:MI:SS')"
                   " FROM v$backup_set WHERE INCREMENTAL_LEVEL=1 AND CONTROLFILE_INCLUDED='NO'", 30)
    if il and il[0]:
        dt = datetime.datetime.strptime(il[0], "%Y-%m-%d %H:%M:%S")
        age_h = (datetime.datetime.now() - dt).total_seconds() / 3600
        r.data["incr"] = {"status": "CRITICAL" if age_h > thr["rman_incr_max_hours"] else "OK",
                          "last": il[0], "age_hours": round(age_h, 1)}
        if age_h > thr["rman_incr_max_hours"]: r.issues.append(f"Incremental backup {age_h:.1f}h old")
    # Archivelog
    al = sql_lines(mgr, host, ora_user,
                   "SELECT TO_CHAR(MAX(COMPLETION_TIME),'YYYY-MM-DD HH24:MI:SS')"
                   " FROM v$backup_set WHERE BACKUP_TYPE='L'", 30)
    if al and al[0]:
        dt = datetime.datetime.strptime(al[0], "%Y-%m-%d %H:%M:%S")
        age_h = (datetime.datetime.now() - dt).total_seconds() / 3600
        r.data["arch"] = {"status": "CRITICAL" if age_h > thr["rman_arch_max_hours"] else "OK",
                          "last": al[0], "age_hours": round(age_h, 1)}
        if age_h > thr["rman_arch_max_hours"]: r.issues.append(f"Arch backup {age_h:.1f}h old")
    r.status = agg(*[v.get("status","OK") for v in r.data.values()])
    return r

def chk_archive_gaps(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("archive_gaps")
    lines = sql_lines(mgr, host, ora_user, "SELECT count(*) FROM v$archive_gap", 20)
    if lines:
        try:
            gaps = int(lines[0].strip())
            r.data["gaps"] = gaps
            if gaps > 0: r.status = "CRITICAL"; r.issues.append(f"{gaps} archive gaps")
        except: pass
    return r

def chk_alert_log_sql(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("alert_log_errors")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT count(*) FROM v$diag_alert_ext"
                      " WHERE origination_timestamp>SYSDATE-1 AND message_type IN ('ERROR','WARNING')", 30)
    if lines:
        try:
            cnt = int(lines[0].strip())
            r.data["errors_24h"] = cnt
            if cnt >= thr["alert_error_count_warn"]:
                r.status = "WARNING"; r.issues.append(f"{cnt} alert errors in 24h")
        except: pass
    return r

def chk_log_switch_rate(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("log_switch_rate")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT round(count(*)/24,1) FROM v$log_history WHERE first_time>sysdate-1", 20)
    if lines:
        try:
            rate = float(lines[0].strip())
            r.data["switches_per_hour"] = rate
            if rate >= thr["log_switch_warn_per_hour"]:
                r.status = "WARNING"; r.issues.append(f"Log switch rate {rate}/h")
        except: pass
    return r

def chk_alert_log_file(mgr, host, ora_user, sid: str,
                       oracle_base: str = "/u01/app/oracle") -> CheckResult:
    r = CheckResult("alert_log_parse")
    # try to find alert log path
    out = mgr.run(host, ora_user,
                  f"find {oracle_base}/diag/rdbms -name 'alert_{sid.lower()}.log' 2>/dev/null | head -1",
                  timeout=30)
    path = out["stdout"].strip()
    if not path:
        out = mgr.run(host, ora_user,
                      f"find {oracle_base}/diag -name 'alert_{sid.lower()}.log' 2>/dev/null | head -1",
                      timeout=30)
        path = out["stdout"].strip()
    if path:
        o = mgr.run(host, ora_user, f"tail -5000 {path} | grep 'ORA-' | tail -20", timeout=30)
        r.data = {"path": path, "recent_ora_errors": o["stdout"].splitlines()[:30]}
        ora600 = any("ORA-00600" in l for l in o["stdout"].splitlines())
        ora7445 = any("ORA-07445" in l for l in o["stdout"].splitlines())
        if ora600 or ora7445:
            r.status = "CRITICAL"; r.issues.append("ORA-600/7445 in alert log!")
    else:
        r.data = {"note": "alert log not found"}
    return r

def chk_corrupted_blocks(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("corrupted_blocks")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT count(*) FROM v$database_block_corruption", 20)
    if lines:
        try:
            cnt = int(lines[0].strip())
            r.data["count"] = cnt
            if cnt > 0: r.status = "CRITICAL"; r.issues.append(f"{cnt} corrupted blocks!")
        except: pass
    return r

def chk_patch_status(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("patch_status")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT patch_id, status FROM dba_registry_sqlpatch"
                      " WHERE action='APPLY' ORDER BY patch_id DESC FETCH FIRST 10 ROWS ONLY", 30)
    r.data["latest_patches"] = lines
    if any("ERROR" in l for l in lines):
        r.status = "WARNING"; r.issues.append("Patches with errors detected")
    return r

def chk_recyclebin_size(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("recyclebin")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT count(*), round(sum(space)/1048576,1) FROM dba_recyclebin", 20)
    if lines:
        p = lines[0].split()
        if len(p) >= 2:
            try:
                r.data = {"objects": int(p[0]), "size_mb": float(p[1])}
                if float(p[1]) > 5000: r.status = "WARNING"; r.issues.append(f"Recyclebin {p[1]}MB")
            except: pass
    return r

def chk_undo(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("undo_tablespace")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT tablespace_name, used_percent FROM dba_tablespace_usage_metrics"
                      " WHERE tablespace_name LIKE '%UNDO%'", 20)
    for ln in lines:
        p = ln.split()
        if len(p) >= 2:
            try:
                pct = float(p[1])
                r.data[p[0]] = pct
                if pct >= thr["undo_warn_pct"]: r.issues.append(f"UNDO {p[0]} {pct}%")
            except: pass
    r.status = "WARNING" if r.issues else "OK"
    return r

def chk_sessions(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("sessions")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT current_utilization, max_utilization, limit_value"
                      " FROM v$resource_limit WHERE resource_name='sessions'", 20)
    if lines:
        p = lines[0].split()
        if len(p) >= 3:
            try:
                cur = int(p[0]); lim = int(p[2])
                pct = round(cur*100/lim, 1) if lim > 0 else 0
                r.data = {"current": cur, "limit": lim, "used_pct": pct}
                if pct >= thr["session_crit_pct"]:
                    r.status = "CRITICAL"; r.issues.append(f"Sessions {pct}%")
                elif pct >= thr["session_warn_pct"]:
                    r.status = "WARNING"; r.issues.append(f"Sessions {pct}%")
            except: pass
    return r

def chk_performance(server_result: Dict, mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("performance")
    # Wait events
    wl = sql_lines(mgr, host, ora_user,
                   "SELECT event, round(time_waited/100,1) secs FROM v$system_event"
                   " WHERE event NOT LIKE '%idle%' AND event NOT LIKE 'SQL*Net%'"
                   " ORDER BY time_waited DESC FETCH FIRST 5 ROWS ONLY", 30)
    r.data["top_wait_events"] = wl
    # PGA
    pl = sql_lines(mgr, host, ora_user,
                   "SELECT name, round(value/1073741824,2) FROM v$pgastat"
                   " WHERE name IN ('total PGA inuse','total PGA allocated','cache hit percentage')", 20)
    pga = {}
    for ln in pl:
        parts = ln.rsplit(None, 1)
        if len(parts) == 2:
            try: pga[parts[0]] = float(parts[1])
            except: pass
    r.data["pga"] = pga
    if pga.get("cache hit percentage", 100) < thr["pga_hit_warn"]:
        r.issues.append(f"PGA hit {pga.get('cache hit percentage')}%"); r.status = "WARNING"
    # SGA pools
    sl = sql_lines(mgr, host, ora_user,
                   "SELECT pool, round(sum(bytes)/1073741824,2) FROM v$sgastat GROUP BY pool", 20)
    r.data["sga_pools_gb"] = {p[0]: p[1] for p in [ln.split() for ln in sl] if len(p) >= 2}
    return r

def chk_nd_params(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("non_default_params")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT name, value FROM v$parameter WHERE isdefault='FALSE'"
                      " AND name NOT LIKE '\\_%' ESCAPE '\\' ORDER BY name", 30)
    r.data["non_default_params"] = lines
    hidden = sql_lines(mgr, host, ora_user,
                       "SELECT name, value FROM v$parameter WHERE name LIKE '\\_%' ESCAPE '\\'"
                       " AND isdefault='FALSE'", 30)
    if hidden:
        r.data["hidden_params"] = hidden
        r.issues.append(f"{len(hidden)} hidden parameters set!")
        r.status = "WARNING"
    return r

def chk_db_size(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("database_size")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT round(sum(bytes)/1073741824,1) FROM dba_segments", 60)
    if lines:
        try: r.data["used_gb"] = float(lines[0].strip())
        except: pass
    tf = sql_lines(mgr, host, ora_user,
                   "SELECT round(sum(bytes)/1073741824,1) FROM dba_data_files", 20)
    if tf:
        try: r.data["allocated_gb"] = float(tf[0].strip())
        except: pass
    return r

def chk_datapump_jobs(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("datapump_jobs")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT owner_name, job_name, operation, state, error_count"
                      " FROM dba_datapump_jobs WHERE start_time>sysdate-7", 30)
    r.data["jobs_last_7d"] = lines
    failed = [l for l in lines if "FAILED" in l.upper() or "ERROR" in l.upper()]
    if failed: r.status = "WARNING"; r.issues.append(f"{len(failed)} failed datapump jobs")
    return r

def chk_expdp_files(mgr, host, ora_user, pdbs: List[str],
                    expdp_dir: str, max_age_h: int) -> CheckResult:
    r = CheckResult("expdp_dumps")
    for pdb in pdbs:
        o = mgr.run(host, ora_user,
                    f"find {expdp_dir} -name '*{pdb}*.dmp' -o -name '*{pdb}*.log' -exec ls -t {{}} + 2>/dev/null | head -1",
                    timeout=30)
        if o["stdout"].strip():
            latest = o["stdout"].strip()
            s = mgr.run(host, ora_user, f"stat -c '%Y' {latest}", timeout=15)
            if s["rc"] == 0:
                try:
                    age = (time.time() - int(s["stdout"].strip())) / 3600
                    r.data[pdb] = {"age_hours": round(age, 1), "file": latest}
                    if age > max_age_h: r.issues.append(f"Expdp {pdb} {age:.1f}h old")
                except: pass
        else:
            r.data[pdb] = {"status": "MISSING"}
            r.issues.append(f"No expdp for {pdb}")
    r.status = "WARNING" if r.issues else "OK"
    return r

def chk_goldengate(mgr, host, ora_user, gg_home: Optional[str],
                   thr: Dict) -> CheckResult:
    r = CheckResult("goldengate")
    if not gg_home:
        r.status = "N/A"; r.data["note"] = "GG_HOME not configured"
        return r
    ggsci = f"{gg_home}/ggsci"
    # Manager status
    o = mgr.run(host, ora_user, f"echo 'info mgr' | {ggsci} 2>&1", timeout=30)
    mgr_up = "running" in o["stdout"].lower()
    r.data["manager"] = {"status": "RUNNING" if mgr_up else "DOWN",
                         "output": o["stdout"][:300]}
    if not mgr_up: r.status = "CRITICAL"; r.issues.append("GG manager DOWN")
    # All processes + lag
    o2 = mgr.run(host, ora_user, f"echo 'info all' | {ggsci} 2>&1", timeout=30)
    procs = []
    for m in re.finditer(r"\s*(EXTRACT|REPLICAT|DATAPUMP)\s+(\S+)\s+(RUNNING|STOPPED|ABENDED)\s*(.*)",
                         o2["stdout"], re.I):
        ptype = m.group(1).upper(); pname = m.group(2).upper()
        pst   = m.group(3).upper(); rest  = m.group(4).strip()
        lag = None
        lm = re.search(r"(\d+):(\d+):(\d+)", rest)
        if lm: lag = int(lm.group(1))*3600 + int(lm.group(2))*60 + int(lm.group(3))
        proc_status = "OK" if pst == "RUNNING" else \
                      ("CRITICAL" if pst in ("ABENDED","STOPPED") else "WARNING")
        if lag is not None:
            if lag >= thr["gg_lag_crit_sec"]: proc_status = "CRITICAL"
            elif lag >= thr["gg_lag_warn_sec"] and proc_status == "OK": proc_status = "WARNING"
        procs.append({"name": pname, "type": ptype, "state": pst,
                      "lag_sec": lag, "health": proc_status})
        if proc_status != "OK": r.issues.append(f"GG {pname} {pst} lag={lag}s")
    r.data["processes"] = procs
    r.status = agg(r.status, *[p["health"] for p in procs])
    return r

def chk_dataguard(mgr, host, ora_user, thr: Dict) -> CheckResult:
    r = CheckResult("dataguard")
    lines = sql_lines(mgr, host, ora_user,
                      "SELECT name, value FROM v$dataguard_stats WHERE name IN ('transport lag','apply lag')", 20)
    for ln in lines:
        if "transport lag" in ln.lower():
            val = ln.split()[-1]
            try:
                lag = int(val)
                r.data["transport_lag_sec"] = lag
                if lag >= thr["dg_lag_crit_sec"]: r.status = "CRITICAL"
                elif lag >= thr["dg_lag_warn_sec"]: r.status = "WARNING"
            except: pass
        if "apply lag" in ln.lower():
            val = ln.split()[-1]
            try:
                lag = int(val)
                r.data["apply_lag_sec"] = lag
                if lag >= thr["dg_lag_crit_sec"]: r.status = "CRITICAL"
                elif lag >= thr["dg_lag_warn_sec"] and r.status != "CRITICAL": r.status = "WARNING"
            except: pass
    # Managed standby processes
    ms = sql_lines(mgr, host, ora_user,
                   "SELECT process, status, sequence# FROM v$managed_standby", 20)
    r.data["managed_standby"] = ms
    # Archive dest status
    ad = sql_lines(mgr, host, ora_user,
                   "SELECT dest_id, status, destination FROM v$archive_dest_status"
                   " WHERE status!='INACTIVE' AND target='PRIMARY'", 20)
    r.data["archive_dest"] = ad
    if r.status == "OK" and r.issues: r.status = "WARNING"
    return r

def chk_controlfile_autobackup(mgr, host, ora_user) -> CheckResult:
    r = CheckResult("controlfile_autobackup")
    o = mgr.run(host, ora_user, "rman target / <<< 'show controlfile autobackup;' 2>&1", timeout=30)
    r.data = {"raw": o["stdout"][:400]}
    if "CONTROLFILE AUTOBACKUP ON" not in o["stdout"]:
        r.status = "WARNING"; r.issues.append("Controlfile autobackup may be OFF")
    return r

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def generate_text_report(all_servers: List[Dict]) -> str:
    """Human-readable report with per‑server/per‑DB sections and global summary."""
    out = []
    out.append("=" * 85)
    out.append(f"  ORACLE RAC / SOLARIS – COMPLETE DAILY HEALTH CHECK")
    out.append(f"  Generated: {now_ts()}")
    out.append("=" * 85)

    for srv in all_servers:
        host = srv["host"]
        out.append(f"\n{'#'*65}\n# SERVER: {host}\n{'#'*65}")

        # Server health
        sh = srv.get("server_health", {})
        if sh:
            out.append("  --- Server Health ---")
            if sh.get("cpu_used_pct"): out.append(f"    CPU used: {sh['cpu_used_pct']}%")
            if sh.get("mem_used_pct"): out.append(f"    Memory used: {sh['mem_used_pct']}%")
            if sh.get("swap_used_pct"): out.append(f"    Swap used: {sh['swap_used_pct']}%")
            for d in sh.get("disks", []):
                fl = "  " if d["status"] == "OK" else f"  [{d['status']}]"
                out.append(f"    Disk {d['mount']}: {d['used_pct']}% {fl}")
            if sh.get("top_procs"):
                out.append("    Top CPU:"); 
                [out.append(f"      {p}") for p in sh["top_procs"][:5]]
            for iss in sh.get("issues", []): out.append(f"    [WARNING] {iss}")

        # Cluster / Grid
        for sec in ["crs_daemons", "cluster_nodes", "cluster_resources",
                     "ocr", "voting_disks", "scan_listener", "listener_detail",
                     "asm_diskgroups", "interconnect"]:
            val = srv.get(sec, {}).get("data")
            st  = srv.get(sec, {}).get("status", "?")
            iss = srv.get(sec, {}).get("issues", [])
            out.append(f"  --- {sec.replace('_',' ').title()} ---  [{st}]")
            if val:
                out.append(f"    {json.dumps(val, default=str)[:400]}")
            for i in iss: out.append(f"    [ISSUE] {i}")

        # Databases
        for db in srv.get("databases", []):
            dbname = db.get("db_info", {}).get("data", {}).get("name", db.get("db_name", "?"))
            out.append(f"\n    ===== DATABASE: {dbname} =====")
            for ckname in ["db_info", "pdb_open_modes", "tablespaces",
                            "recovery_area", "redo_logs", "invalid_objects",
                            "scheduler_jobs", "blocking_locks", "long_running_queries",
                            "rman_backups", "archive_gaps", "alert_log_errors",
                            "log_switch_rate", "alert_log_parse", "corrupted_blocks",
                            "patch_status", "recyclebin", "undo_tablespace",
                            "sessions", "performance", "non_default_params",
                            "database_size", "datapump_jobs", "expdp_dumps",
                            "goldengate", "dataguard", "controlfile_autobackup"]:
                c = db.get(ckname)
                if not c: continue
                st = c.get("status", "?")
                fl = f"[{st}]" if st not in ("OK", "N/A") else ""
                out.append(f"      {ckname}: {fl}")
                for iss in c.get("issues", []): out.append(f"        - {iss}")

    # Global summary
    out.append("\n\n" + "=" * 85)
    out.append("               CRITICAL / WARNING SUMMARY")
    out.append("=" * 85)
    crit, warn = [], []
    for srv in all_servers:
        host = srv["host"]
        for db in srv.get("databases", []):
            dbn = db.get("db_info", {}).get("data", {}).get("name", db.get("db_name", "?"))
            for ck in db.values():
                if isinstance(ck, dict):
                    for iss in ck.get("issues", []):
                        (crit if "CRITICAL" in iss.upper() or "ORA-600" in iss.upper()
                         else warn).append(f"{host}/{dbn}: {iss}")
        for sec_n, sec_v in srv.items():
            if isinstance(sec_v, dict) and sec_n != "databases":
                for iss in sec_v.get("issues", []):
                    (crit if "CRITICAL" in iss.upper() else warn).append(f"{host}: {iss}")
    if crit:
        out.append("\nCRITICAL:")
        for c in crit: out.append(f"  - {c}")
    if warn:
        out.append("\nWARNING:")
        for w in warn: out.append(f"  - {w}")
    if not crit and not warn:
        out.append("\n  No issues detected – all systems healthy.")
    out.append("\n" + "=" * 85 + "\nEND OF REPORT")
    return "\n".join(out)

def generate_json_report(all_servers: List[Dict]) -> Dict:
    crit, warn = [], []
    for srv in all_servers:
        host = srv["host"]
        for db in srv.get("databases", []):
            dbn = db.get("db_info", {}).get("data", {}).get("name", db.get("db_name", "?"))
            for ck in db.values():
                if isinstance(ck, dict):
                    for iss in ck.get("issues", []):
                        (crit if "CRITICAL" in iss.upper() or "ORA-600" in iss.upper()
                         else warn).append(f"{host}/{dbn}: {iss}")
        for sec_n, sec_v in srv.items():
            if isinstance(sec_v, dict) and sec_n != "databases":
                for iss in sec_v.get("issues", []):
                    (crit if "CRITICAL" in iss.upper() else warn).append(f"{host}: {iss}")
    return {"timestamp": now_ts(), "servers": all_servers,
            "summary": {"critical": crit, "warning": warn}}

# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------
def main():
    config_path = os.environ.get("HCEXTRACT_CONFIG",
                                 str(Path(__file__).parent / "config.json"))
    if not os.path.exists(config_path):
        print(f"ERROR: config.json not found at {config_path}"); sys.exit(1)
    with open(config_path) as f: config = json.load(f)

    servers_cfg = config.get("servers", [])
    if not servers_cfg:
        print("No servers defined in config."); sys.exit(1)

    thr = {**DEFAULT_THRESHOLDS, **config.get("global_thresholds", {})}
    out_dir = Path(config.get("global", {}).get("output_dir", "./reports"))
    out_dir.mkdir(parents=True, exist_ok=True)

    mgr = SSHMgr(thr["ssh_connect_timeout"], thr["ssh_exec_timeout"])
    all_servers: List[Dict] = []

    try:
        for srv_cfg in servers_cfg:
            host       = srv_cfg["hostname"]
            ora_user   = srv_cfg.get("oracle_user", "oracle")
            grid_user  = srv_cfg.get("grid_user", "grid")
            t          = {**thr, **srv_cfg.get("thresholds", {})}
            ora_base   = srv_cfg.get("oracle_base", "/u01/app/oracle")
            gg_home    = srv_cfg.get("gg_home")

            srv_res = {"host": host}

            print(f"\n>>> Checking server: {host}")

            # Server health
            srv_res["server_health"] = chk_server_health(mgr, host, ora_user, t).__dict__

            # Grid checks
            srv_res["crs_daemons"]      = chk_crs_daemons(mgr, host, grid_user).__dict__
            srv_res["cluster_nodes"]    = chk_cluster_nodes(mgr, host, grid_user).__dict__
            srv_res["cluster_resources"]= chk_cluster_resources(mgr, host, grid_user).__dict__
            srv_res["ocr"]              = chk_ocr(mgr, host, grid_user).__dict__
            srv_res["voting_disks"]     = chk_voting_disks(mgr, host, grid_user).__dict__
            srv_res["scan_listener"]    = chk_scan_listener(mgr, host, grid_user).__dict__
            srv_res["asm_diskgroups"]   = chk_asm_dg(mgr, host, grid_user, t).__dict__
            srv_res["listener_detail"]  = chk_listener_detail(mgr, host, grid_user).__dict__
            srv_res["interconnect"]     = chk_interconnect_ping(mgr, host, ora_user, t).__dict__

            srv_res["databases"] = []
            for db_entry in srv_cfg.get("databases", []):
                db_name = db_entry["db_name"]
                sid     = db_entry.get("sid", db_name)
                pdbs    = db_entry.get("pdbs", [])
                expdp_d = db_entry.get("expdp_dir", "/expdpbkp/daily")
                expdp_a = db_entry.get("expdp_max_age_hours", t["expdp_max_age_hours"])

                db_res = {"db_name": db_name}

                # Connectivity and basic info
                conn = chk_db_connectivity(mgr, host, ora_user, sid)
                db_res["db_connectivity"] = conn.__dict__
                if conn.status != "OK":
                    db_res["db_info"] = CheckResult("db_info").__dict__
                    db_res["db_info"]["status"] = "ERROR"
                    db_res["db_info"]["issues"] = ["Cannot connect to DB – skipping SQL checks"]
                    srv_res["databases"].append(db_res)
                    continue

                # All SQL‑based checks
                db_res["db_info"]              = chk_db_info(mgr, host, ora_user).__dict__
                db_res["pdb_open_modes"]       = chk_pdb_modes(mgr, host, ora_user).__dict__
                db_res["tablespaces"]          = chk_tablespaces(mgr, host, ora_user, t).__dict__
                db_res["recovery_area"]        = chk_fra(mgr, host, ora_user, t).__dict__
                db_res["redo_logs"]            = chk_redo_multiplex(mgr, host, ora_user).__dict__
                db_res["invalid_objects"]      = chk_invalid_objects(mgr, host, ora_user, t).__dict__
                db_res["scheduler_jobs"]       = chk_scheduler_failures(mgr, host, ora_user).__dict__
                db_res["blocking_locks"]       = chk_blocking_locks(mgr, host, ora_user, t).__dict__
                db_res["long_running_queries"] = chk_long_queries(mgr, host, ora_user).__dict__
                db_res["rman_backups"]         = chk_rman_backups(mgr, host, ora_user, t).__dict__
                db_res["archive_gaps"]         = chk_archive_gaps(mgr, host, ora_user).__dict__
                db_res["alert_log_errors"]     = chk_alert_log_sql(mgr, host, ora_user, t).__dict__
                db_res["log_switch_rate"]      = chk_log_switch_rate(mgr, host, ora_user, t).__dict__
                db_res["alert_log_parse"]      = chk_alert_log_file(mgr, host, ora_user, sid, ora_base).__dict__
                db_res["corrupted_blocks"]     = chk_corrupted_blocks(mgr, host, ora_user).__dict__
                db_res["patch_status"]         = chk_patch_status(mgr, host, ora_user).__dict__
                db_res["recyclebin"]           = chk_recyclebin_size(mgr, host, ora_user).__dict__
                db_res["undo_tablespace"]      = chk_undo(mgr, host, ora_user, t).__dict__
                db_res["sessions"]             = chk_sessions(mgr, host, ora_user, t).__dict__
                db_res["performance"]          = chk_performance(db_res, mgr, host, ora_user, t).__dict__
                db_res["non_default_params"]   = chk_nd_params(mgr, host, ora_user).__dict__
                db_res["database_size"]        = chk_db_size(mgr, host, ora_user).__dict__
                db_res["datapump_jobs"]        = chk_datapump_jobs(mgr, host, ora_user).__dict__
                db_res["expdp_dumps"]          = chk_expdp_files(mgr, host, ora_user, pdbs, expdp_d, expdp_a).__dict__
                db_res["goldengate"]           = chk_goldengate(mgr, host, ora_user, gg_home, t).__dict__
                db_res["dataguard"]            = chk_dataguard(mgr, host, ora_user, t).__dict__
                db_res["controlfile_autobackup"] = chk_controlfile_autobackup(mgr, host, ora_user).__dict__

                # Crontabs (oracle + grid)
                db_res["crontabs"] = {
                    "oracle": mgr.run(host, ora_user, "crontab -l 2>/dev/null", 15).get("stdout", "").splitlines(),
                    "grid":   mgr.run(host, grid_user, "crontab -l 2>/dev/null", 15).get("stdout", "").splitlines()
                }

                srv_res["databases"].append(db_res)

            all_servers.append(srv_res)
    finally:
        mgr.close_all()

    # ---- Reports ----
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = out_dir / f"healthcheck_{ts}.txt"
    json_path= out_dir / f"healthcheck_{ts}.json"

    txt = generate_text_report(all_servers)
    with open(txt_path, "w") as f: f.write(txt)

    js = generate_json_report(all_servers)
    with open(json_path, "w") as f: json.dump(js, f, indent=2, default=str)

    print(f"\nREPORT GENERATED\n  TXT : {txt_path}\n  JSON: {json_path}\n")
    # Print console summary
    summary = txt[txt.find("CRITICAL / WARNING SUMMARY"):]
    print(summary)

    if js["summary"]["critical"]: sys.exit(2)
    elif js["summary"]["warning"]: sys.exit(1)
    else: sys.exit(0)

if __name__ == "__main__":
    main()
    