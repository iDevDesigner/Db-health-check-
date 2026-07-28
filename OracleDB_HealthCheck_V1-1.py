#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
==============================================================================
 Oracle Database Health Check  –  V1
 Connection : python-oracledb (thick/thin) or cx_Oracle fallback
 Processing : pandas DataFrames for all SQL results
 Report     : identical make_result / summary structure to HealthCheck_V5

 CHECKS PERFORMED
  1.  Connectivity            – can we connect? user/version/driver
  2.  Database Info           – open mode, role, log mode, flashback, uptime
  3.  Instance / Node Status  – GV$INSTANCE (RAC-aware)
  4.  PDB Status              – V$PDBS open mode (CDB only)
  5.  Tablespace Usage        – permanent + temp (WARNING / CRITICAL thresholds)
  6.  Undo Usage              – active / unexpired / expired extents
  7.  Fast Recovery Area      – space used %, file type breakdown
  8.  ASM Storage             – disk group % used, offline disks
  9.  RMAN Full Backup        – last full; CRITICAL if > 7 days
 10.  RMAN Incremental Backup – last incremental; CRITICAL if > 25 h
 11.  RMAN Archive Backup     – last arch log backup; CRITICAL if > 2 h
 12.  RMAN Failed Jobs        – failed RMAN jobs in last 7 days
 13.  RMAN Oldest Backup      – oldest available backup piece
 14.  Scheduler Stats         – enabled/disabled/broken/running counts
 15.  Failed Scheduler Jobs   – jobs that failed in last 24 h
 16.  Long Running Jobs       – scheduler jobs running > threshold
 17.  Disabled Scheduler Jobs – non-system disabled jobs
 18.  Invalid Objects         – DBA_OBJECTS STATUS='INVALID' (non-system)
 19.  Blocking Sessions       – sessions blocking others > 5 min
 20.  Long Running Sessions   – active user sessions > 1 h
 21.  Redo Log Status         – redo log group state (INACTIVE/ACTIVE/CURRENT)
 22.  Archive Destinations    – V$ARCHIVE_DEST ERROR status
 23.  Data Guard Status       – role, protection mode, apply/transport lag
 24.  Alert Log SQL           – recent ORA- errors via V$DIAG_ALERT_EXT
 25.  Top Wait Events         – top 10 non-idle system wait events
 26.  Memory (SGA / PGA)      – buffer cache, shared pool, PGA usage
==============================================================================
"""

from __future__ import print_function

import os
import re
import sys
from datetime import datetime

# ── Oracle driver  ─────────────────────────────────────────────────────────────
# Try python-oracledb (official Accelerated Python Driver) first.
# Thin mode requires no Oracle Client; thick mode uses the local Oracle libs.
try:
    import oracledb                     # pip install oracledb
    try:
        oracledb.init_oracle_client()   # activate thick mode (uses Oracle Client)
        DRIVER = "oracledb-thick"
    except Exception:
        DRIVER = "oracledb-thin"        # thin mode – pure Python, no client needed
    AUTH_SYSDBA = oracledb.AUTH_MODE_SYSDBA
except ImportError:
    try:
        import cx_Oracle as oracledb    # pip install cx_Oracle (legacy)
        DRIVER = "cx_Oracle"
        AUTH_SYSDBA = oracledb.SYSDBA
    except ImportError:
        oracledb   = None
        DRIVER     = None
        AUTH_SYSDBA = None

# ── Pandas ────────────────────────────────────────────────────────────────────
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    pd         = None
    HAS_PANDAS = False

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# ── Tablespace / storage thresholds (%) ──────────────────────────────────────
TS_WARN_PCT           = 80
TS_CRIT_PCT           = 90
FRA_WARN_PCT          = 80
FRA_CRIT_PCT          = 90
ASM_WARN_PCT          = 80
ASM_CRIT_PCT          = 90
UNDO_WARN_PCT         = 70    # % of undo space in ACTIVE state

# ── RMAN backup thresholds ───────────────────────────────────────────────────
RMAN_FULL_WARN_DAYS   = 5     # last full backup older than N days  → WARNING
RMAN_FULL_CRIT_DAYS   = 7     # last full backup older than N days  → CRITICAL
RMAN_INCR_WARN_HOURS  = 20    # last incremental older than N hours → WARNING
RMAN_INCR_CRIT_HOURS  = 25    # last incremental older than N hours → CRITICAL
RMAN_ARCH_WARN_HOURS  = 1.5   # last arch log backup older          → WARNING
RMAN_ARCH_CRIT_HOURS  = 2.0   # last arch log backup older          → CRITICAL

# ── Session / job thresholds ─────────────────────────────────────────────────
BLOCKING_WARN_SECS    = 300   # blocking session > 5 min  → WARNING
BLOCKING_CRIT_SECS    = 1800  # blocking session > 30 min → CRITICAL
LONG_SESSION_WARN_H   = 1     # active session > 1 h      → WARNING
LONG_SESSION_CRIT_H   = 4     # active session > 4 h      → CRITICAL
LONG_JOB_WARN_H       = 2     # scheduler job running > 2 h → WARNING
LONG_JOB_CRIT_H       = 6     # scheduler job running > 6 h → CRITICAL

# ── Alert log look-back ───────────────────────────────────────────────────────
ALERT_LOG_HOURS       = 24    # scan last N hours of alert log

# ── System / Oracle owners to exclude from invalid-objects / job checks ───────
_SYS_OWNERS = frozenset({
    "SYS", "SYSTEM", "DBSNMP", "SYSMAN", "OUTLN", "MDSYS", "ORDSYS",
    "EXFSYS", "DMSYS", "WMSYS", "CTXSYS", "ANONYMOUS", "XDB",
    "ORDPLUGINS", "OLAPSYS", "PUBLIC", "LBACSYS", "OJVMSYS", "APPQOSSYS",
    "GSMADMIN_INTERNAL", "ORACLE_OCM", "AUDSYS", "DVF", "DVSYS",
    "FLOWS_FILES", "APEX_PUBLIC_USER",
})

# ── Database definitions ──────────────────────────────────────────────────────
#   scan_name   : SCAN hostname (or single-node hostname for non-RAC)
#   db_name     : DB_UNIQUE_NAME or DB_NAME
#   service_name: Oracle service name for the connection
#   port        : listener port (default 1521)
#   is_cdb      : True → use CDB_* views; enables PDB status check
#   username    : monitoring user (needs SELECT_CATALOG_ROLE + SELECT ANY DICT)
#   password    : credential (prefer env vars below)
#   role        : None (normal) | "SYSDBA" for privileged checks
#   rman_check  : enable RMAN backup checks
#   dg_check    : enable Data Guard status check
DATABASES = [
    {
        "name":         "PRODCDB1",
        "scan_name":    "prod-scan.example.com",
        "db_name":      "PRODCDB",
        "service_name": "PRODCDB",
        "port":         1521,
        "is_cdb":       True,
        "username":     os.environ.get("ORA_MON_USER", "C##MONITOR"),
        "password":     os.environ.get("ORA_MON_PASS", "Monitor#1234"),
        "role":         None,
        "rman_check":   True,
        "dg_check":     False,
    },
    {
        "name":         "PRODDB2",
        "scan_name":    "prod2-scan.example.com",
        "db_name":      "PRODDB2",
        "service_name": "PRODDB2",
        "port":         1521,
        "is_cdb":       False,
        "username":     os.environ.get("ORA_MON_USER", "MONITOR"),
        "password":     os.environ.get("ORA_MON_PASS", "Monitor#1234"),
        "role":         None,
        "rman_check":   True,
        "dg_check":     True,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
#  STATUS CONSTANTS  (identical to HealthCheck_V5)
# ─────────────────────────────────────────────────────────────────────────────
S_OK       = "OK"
S_WARNING  = "WARNING"
S_CRITICAL = "CRITICAL"
S_ERROR    = "ERROR"
S_NA       = "N/A"

# ─────────────────────────────────────────────────────────────────────────────
#  UNIFIED CHECK-RESULT FACTORY  (identical to HealthCheck_V5)
# ─────────────────────────────────────────────────────────────────────────────
def make_result(check_name, status, details, **extra):
    """Return a standardised check-result dict."""
    r = {"check_name": check_name, "status": status, "details": str(details)}
    r.update(extra)
    return r

# ─────────────────────────────────────────────────────────────────────────────
#  VALUE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _num(val, default=0.0):
    """Safely coerce to float; return default on None / NaN / error."""
    try:
        if val is None:
            return default
        if HAS_PANDAS and pd.isna(val):
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


def _str(val, default="N/A"):
    """Safely coerce to stripped string; return default on None."""
    if val is None:
        return default
    if HAS_PANDAS:
        try:
            if pd.isna(val):
                return default
        except TypeError:
            pass
    return str(val).strip() or default


def _val(row, col, default=None):
    """Get a named column from an itertuples Row or plain dict."""
    try:
        return getattr(row, col, default) if not isinstance(row, dict) else row.get(col, default)
    except Exception:
        return default

# ─────────────────────────────────────────────────────────────────────────────
#  CONNECTION
# ─────────────────────────────────────────────────────────────────────────────
def connect_db(db_cfg):
    """
    Open an Oracle connection for the given config entry.
    Returns (connection, None) on success or (None, error_string) on failure.
    """
    if oracledb is None:
        return None, (
            "No Oracle driver available. "
            "Install python-oracledb:  pip install oracledb"
        )
    try:
        dsn = "{host}:{port}/{service}".format(
            host    = db_cfg["scan_name"],
            port    = db_cfg.get("port", 1521),
            service = db_cfg["service_name"],
        )
        kwargs = dict(user=db_cfg["username"], password=db_cfg["password"], dsn=dsn)
        role = db_cfg.get("role")
        if role and role.upper() == "SYSDBA":
            kwargs["mode"] = AUTH_SYSDBA
        conn = oracledb.connect(**kwargs)
        return conn, None
    except Exception as exc:
        return None, "Connection failed to {s}: {e}".format(
            s=db_cfg.get("service_name", "?"), e=exc)


def _close_conn(conn):
    """Silently close a DB connection."""
    if conn:
        try:
            conn.close()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  QUERY HELPER
# ─────────────────────────────────────────────────────────────────────────────
class _SimpleDF:
    """Minimal DataFrame-like wrapper for when pandas is not available."""
    def __init__(self, cols, rows):
        self.columns = cols
        self._rows   = [dict(zip(cols, r)) for r in rows]
        self.empty   = len(rows) == 0
    def itertuples(self, index=False):
        for r in self._rows:
            yield type("Row", (), r)()
    def __len__(self):
        return len(self._rows)


def run_query(conn, sql):
    """
    Execute *sql* and return (DataFrame | _SimpleDF, error_string | None).
    Column names are normalised to lower-case.
    On failure returns (empty container, error_string).
    """
    try:
        if HAS_PANDAS:
            df = pd.read_sql_query(sql, conn)
            df.columns = [c.lower() for c in df.columns]
            return df, None
        # Fallback: raw cursor
        cur = conn.cursor()
        cur.execute(sql)
        cols = [d[0].lower() for d in cur.description] if cur.description else []
        rows = cur.fetchall()
        cur.close()
        return _SimpleDF(cols, rows), None
    except Exception as exc:
        empty = pd.DataFrame() if HAS_PANDAS else _SimpleDF([], [])
        return empty, "Query error: {e}".format(e=exc)


def _rows(df):
    """Uniform row iterator for both pandas DataFrames and _SimpleDF."""
    if HAS_PANDAS and isinstance(df, pd.DataFrame):
        return df.itertuples(index=False)
    return df.itertuples(index=False)


def _empty(df):
    if HAS_PANDAS and isinstance(df, pd.DataFrame):
        return df.empty
    return getattr(df, "empty", True)

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 1 – CONNECTIVITY
# ─────────────────────────────────────────────────────────────────────────────
def check_connectivity(conn, db_cfg):
    """Confirm the connection works and identify the user / db / version."""
    chk = "CONNECTIVITY"
    sql = """
        SELECT SYS_CONTEXT('USERENV','SESSION_USER')    session_user,
               SYS_CONTEXT('USERENV','DB_NAME')         db_name,
               SYS_CONTEXT('USERENV','CON_NAME')        con_name,
               SYS_CONTEXT('USERENV','SERVER_HOST')     server_host,
               SYS_CONTEXT('USERENV','DB_UNIQUE_NAME')  db_unique_name
        FROM DUAL
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_CRITICAL, "Connected but test query failed: {e}".format(e=err))]
    for row in _rows(df):
        return [make_result(
            chk, S_OK,
            "User={u} DB={d} UniqueName={un} Container={c} Host={h} Driver={dr}".format(
                u  = _str(_val(row, "session_user")),
                d  = _str(_val(row, "db_name")),
                un = _str(_val(row, "db_unique_name")),
                c  = _str(_val(row, "con_name")),
                h  = _str(_val(row, "server_host")),
                dr = DRIVER,
            ),
        )]
    return [make_result(chk, S_WARNING, "Connection OK but DUAL returned no rows")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 2 – DATABASE INFO
# ─────────────────────────────────────────────────────────────────────────────
def check_db_info(conn, db_cfg):
    """General database metadata from V$DATABASE and V$INSTANCE."""
    chk = "DB_INFO"
    sql = """
        SELECT D.NAME               db_name,
               D.DB_UNIQUE_NAME     db_unique_name,
               D.LOG_MODE           log_mode,
               D.OPEN_MODE          open_mode,
               D.CDB                cdb,
               D.DATABASE_ROLE      db_role,
               D.PROTECTION_MODE    protection_mode,
               D.FLASHBACK_ON       flashback_on,
               D.SWITCHOVER_STATUS  switchover_status,
               I.INSTANCE_NAME      instance_name,
               I.HOST_NAME          host_name,
               I.VERSION            version,
               I.STATUS             inst_status,
               I.DATABASE_STATUS    db_status,
               I.ACTIVE_STATE       active_state,
               I.LOGINS             logins,
               I.PARALLEL           parallel,
               TO_CHAR(I.STARTUP_TIME,'YYYY-MM-DD HH24:MI') startup_time,
               ROUND((SYSDATE - I.STARTUP_TIME) * 24, 1)    uptime_hours
        FROM   V$DATABASE D, V$INSTANCE I
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "V$DATABASE / V$INSTANCE query failed: {e}".format(e=err))]

    results = []
    for row in _rows(df):
        open_mode  = _str(_val(row, "open_mode"))
        inst_st    = _str(_val(row, "inst_status"))
        db_st      = _str(_val(row, "db_status"))
        logins     = _str(_val(row, "logins"))
        uptime_h   = _num(_val(row, "uptime_hours"))
        log_mode   = _str(_val(row, "log_mode"))

        if open_mode not in ("READ WRITE", "READ ONLY"):
            s = S_CRITICAL
        elif inst_st != "OPEN" or db_st != "ACTIVE":
            s = S_CRITICAL
        elif logins == "RESTRICTED":
            s = S_WARNING
        elif log_mode != "ARCHIVELOG":
            s = S_WARNING    # NOARCHIVELOG is risky for production
        else:
            s = S_OK

        results.append(make_result(
            chk, s,
            "DB={d} Role={r} OpenMode={m} InstStatus={is_} DBStatus={ds} "
            "Version={v} Host={h} Uptime={u:.1f}h Logins={l} "
            "LogMode={lm} Flashback={fb} CDB={cdb} RAC={rac}".format(
                d   = _str(_val(row, "db_name")),
                r   = _str(_val(row, "db_role")),
                m   = open_mode,
                is_ = inst_st,
                ds  = db_st,
                v   = _str(_val(row, "version")),
                h   = _str(_val(row, "host_name")),
                u   = uptime_h,
                l   = logins,
                lm  = log_mode,
                fb  = _str(_val(row, "flashback_on")),
                cdb = _str(_val(row, "cdb")),
                rac = _str(_val(row, "parallel")),
            ),
            open_mode   = open_mode,
            db_role     = _str(_val(row, "db_role")),
            version     = _str(_val(row, "version")),
            uptime_h    = uptime_h,
            is_rac      = _str(_val(row, "parallel")) == "YES",
        ))
    return results or [make_result(chk, S_ERROR, "No rows from V$DATABASE/V$INSTANCE")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 3 – INSTANCE / NODE STATUS  (RAC-aware via GV$INSTANCE)
# ─────────────────────────────────────────────────────────────────────────────
def check_instance_nodes(conn, db_cfg):
    """Check every RAC instance via GV$INSTANCE; falls back to V$INSTANCE."""
    chk = "INSTANCE_NODES"
    sql = """
        SELECT INST_ID,
               INSTANCE_NAME,
               HOST_NAME,
               STATUS,
               DATABASE_STATUS,
               ACTIVE_STATE,
               LOGINS,
               PARALLEL,
               TO_CHAR(STARTUP_TIME,'YYYY-MM-DD HH24:MI') startup_time
        FROM   GV$INSTANCE
        ORDER  BY INST_ID
    """
    df, err = run_query(conn, sql)
    if err:
        sql2 = sql.replace("GV$INSTANCE", "V$INSTANCE").replace("INST_ID,", "1 INST_ID,")
        df, err2 = run_query(conn, sql2)
        if err2:
            return [make_result(chk, S_ERROR, "GV$INSTANCE / V$INSTANCE query failed: {e}".format(e=err))]

    results = []
    for row in _rows(df):
        status     = _str(_val(row, "status"))
        db_status  = _str(_val(row, "database_status"))
        logins     = _str(_val(row, "logins"))
        inst_id    = _str(_val(row, "inst_id"))

        if status != "OPEN" or db_status != "ACTIVE":
            s = S_CRITICAL
        elif logins == "RESTRICTED":
            s = S_WARNING
        else:
            s = S_OK

        results.append(make_result(
            chk, s,
            "Inst={i} Name={n} Host={h} Status={st} DBStatus={ds} "
            "ActiveState={as_} Logins={l} RAC={r} StartTime={t}".format(
                i   = inst_id,
                n   = _str(_val(row, "instance_name")),
                h   = _str(_val(row, "host_name")),
                st  = status,
                ds  = db_status,
                as_ = _str(_val(row, "active_state")),
                l   = logins,
                r   = _str(_val(row, "parallel")),
                t   = _str(_val(row, "startup_time")),
            ),
            inst_id = inst_id,
            host    = _str(_val(row, "host_name")),
        ))
    return results or [make_result(chk, S_WARNING, "No instance rows returned")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 4 – PDB STATUS  (CDB only)
# ─────────────────────────────────────────────────────────────────────────────
def check_pdb_status(conn, db_cfg):
    """Check PDB open modes via V$PDBS (CDB only)."""
    chk = "PDB_STATUS"
    if not db_cfg.get("is_cdb", False):
        return [make_result(chk, S_NA, "Non-CDB – PDB check not applicable")]

    sql = """
        SELECT CON_ID,
               NAME,
               OPEN_MODE,
               RESTRICTED,
               TO_CHAR(OPEN_TIME,'YYYY-MM-DD HH24:MI') open_time
        FROM   V$PDBS
        WHERE  CON_ID > 2
        ORDER  BY CON_ID
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "V$PDBS query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_WARNING, "No user PDBs found in this CDB")]

    results = []
    for row in _rows(df):
        open_mode  = _str(_val(row, "open_mode"))
        restricted = _str(_val(row, "restricted"))
        pdb_name   = _str(_val(row, "name"))

        if open_mode == "READ WRITE" and restricted == "NO":
            s = S_OK
        elif open_mode == "READ ONLY":
            s = S_WARNING
        elif open_mode == "MOUNTED":
            s = S_CRITICAL
        elif restricted == "YES":
            s = S_WARNING
        else:
            s = S_CRITICAL

        results.append(make_result(
            chk, s,
            "PDB={n} ConID={c} OpenMode={m} Restricted={r} OpenTime={t}".format(
                n = pdb_name,
                c = _str(_val(row, "con_id")),
                m = open_mode,
                r = restricted,
                t = _str(_val(row, "open_time")),
            ),
            pdb_name = pdb_name, open_mode = open_mode,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 5 – TABLESPACE USAGE  (permanent + temp)
# ─────────────────────────────────────────────────────────────────────────────
def check_tablespace(conn, db_cfg):
    """Check permanent and temp tablespace utilisation."""
    chk = "TABLESPACE"
    pfx = "CDB" if db_cfg.get("is_cdb") else "DBA"
    results = []

    # ── Permanent tablespaces ─────────────────────────────────────────────────
    sql_perm = """
        SELECT df.tablespace_name,
               df.total_mb,
               ROUND(NVL(df.total_mb - fs.free_mb, df.total_mb), 1) used_mb,
               ROUND(NVL(fs.free_mb, 0), 1) free_mb,
               ROUND(NVL((df.total_mb - fs.free_mb) / NULLIF(df.total_mb,0), 1) * 100, 1) pct_used,
               df.autoextend
        FROM (
            SELECT tablespace_name,
                   ROUND(SUM(bytes)/1048576, 1) total_mb,
                   MAX(CASE WHEN autoextensible='YES' THEN 'YES' ELSE 'NO' END) autoextend
            FROM   {pfx}_DATA_FILES
            GROUP  BY tablespace_name
        ) df
        LEFT JOIN (
            SELECT tablespace_name, ROUND(SUM(bytes)/1048576, 1) free_mb
            FROM   {pfx}_FREE_SPACE
            GROUP  BY tablespace_name
        ) fs ON df.tablespace_name = fs.tablespace_name
        ORDER  BY pct_used DESC NULLS LAST
    """.format(pfx=pfx)

    df_perm, err = run_query(conn, sql_perm)
    if err:
        results.append(make_result(chk, S_ERROR, "Permanent TS query failed: {e}".format(e=err)))
    else:
        for row in _rows(df_perm):
            ts   = _str(_val(row, "tablespace_name"))
            pct  = _num(_val(row, "pct_used"))
            tot  = _num(_val(row, "total_mb"))
            used = _num(_val(row, "used_mb"))
            free = _num(_val(row, "free_mb"))
            aext = _str(_val(row, "autoextend"))
            s    = S_CRITICAL if pct >= TS_CRIT_PCT else (S_WARNING if pct >= TS_WARN_PCT else S_OK)
            results.append(make_result(
                chk, s,
                "TS={n} Used={p}% Total={t:.0f}MB Used={u:.0f}MB Free={f:.0f}MB AutoExt={a}".format(
                    n=ts, p=pct, t=tot, u=used, f=free, a=aext),
                ts_name=ts, ts_type="PERM", pct_used=pct,
            ))

    # ── Temp tablespaces ──────────────────────────────────────────────────────
    sql_temp = """
        SELECT tablespace_name,
               ROUND(tablespace_size  / 1048576, 1) total_mb,
               ROUND(NVL(free_space,0) / 1048576, 1) free_mb,
               ROUND((1 - NVL(free_space,0)/NULLIF(tablespace_size,0)) * 100, 1) pct_used
        FROM   DBA_TEMP_FREE_SPACE
        ORDER  BY pct_used DESC NULLS LAST
    """
    df_tmp, err2 = run_query(conn, sql_temp)
    if err2:
        results.append(make_result(chk, S_ERROR, "Temp TS query failed: {e}".format(e=err2)))
    else:
        for row in _rows(df_tmp):
            ts   = _str(_val(row, "tablespace_name"))
            pct  = _num(_val(row, "pct_used"))
            tot  = _num(_val(row, "total_mb"))
            free = _num(_val(row, "free_mb"))
            s    = S_CRITICAL if pct >= TS_CRIT_PCT else (S_WARNING if pct >= TS_WARN_PCT else S_OK)
            results.append(make_result(
                chk, s,
                "TEMP_TS={n} Used={p}% Total={t:.0f}MB Free={f:.0f}MB".format(
                    n=ts, p=pct, t=tot, f=free),
                ts_name=ts, ts_type="TEMP", pct_used=pct,
            ))

    return results or [make_result(chk, S_WARNING, "No tablespace data returned")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 6 – UNDO USAGE
# ─────────────────────────────────────────────────────────────────────────────
def check_undo(conn, db_cfg):
    """Check UNDO tablespace active / unexpired / expired breakdown."""
    chk = "UNDO"
    sql = """
        SELECT tablespace_name,
               ROUND(SUM(bytes)/1048576, 1)                                                  total_mb,
               ROUND(SUM(CASE WHEN status='ACTIVE'    THEN bytes ELSE 0 END)/1048576, 1)    active_mb,
               ROUND(SUM(CASE WHEN status='UNEXPIRED' THEN bytes ELSE 0 END)/1048576, 1)    unexpired_mb,
               ROUND(SUM(CASE WHEN status='EXPIRED'   THEN bytes ELSE 0 END)/1048576, 1)    expired_mb,
               COUNT(*)                                                                      extents
        FROM   DBA_UNDO_EXTENTS
        GROUP  BY tablespace_name
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "Undo query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_OK, "No UNDO extents found (may be newly created DB)")]

    # Undo retention parameter
    ret_df, _ = run_query(conn, "SELECT VALUE undo_retention FROM V$PARAMETER WHERE NAME='undo_retention'")
    undo_ret = "?"
    for r in _rows(ret_df):
        undo_ret = _str(_val(r, "undo_retention"))

    results = []
    for row in _rows(df):
        ts          = _str(_val(row, "tablespace_name"))
        total_mb    = _num(_val(row, "total_mb"))
        active_mb   = _num(_val(row, "active_mb"))
        unexpired_mb = _num(_val(row, "unexpired_mb"))
        expired_mb  = _num(_val(row, "expired_mb"))
        pct_active  = round(active_mb / max(total_mb, 1) * 100, 1)
        s = S_CRITICAL if pct_active >= TS_CRIT_PCT else (S_WARNING if pct_active >= UNDO_WARN_PCT else S_OK)
        results.append(make_result(
            chk, s,
            "UNDO_TS={n} Total={t:.0f}MB Active={a:.0f}MB({p}%) "
            "Unexpired={u:.0f}MB Expired={e:.0f}MB UndoRetention={r}s".format(
                n=ts, t=total_mb, a=active_mb, p=pct_active,
                u=unexpired_mb, e=expired_mb, r=undo_ret),
            ts_name=ts, active_pct=pct_active,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 7 – FAST RECOVERY AREA  (FRA / Recovery Destination)
# ─────────────────────────────────────────────────────────────────────────────
def check_fra(conn, db_cfg):
    """Check Fast Recovery Area total usage and per-file-type breakdown."""
    chk = "FAST_RECOVERY_AREA"
    results = []

    # Overall FRA usage
    sql_fra = """
        SELECT NAME,
               ROUND(SPACE_LIMIT/1073741824, 2)        limit_gb,
               ROUND(SPACE_USED /1073741824, 2)        used_gb,
               ROUND(SPACE_RECLAIMABLE/1073741824, 2)  reclaimable_gb,
               ROUND(SPACE_USED / NULLIF(SPACE_LIMIT,0) * 100, 1) pct_used,
               NUMBER_OF_FILES
        FROM   V$RECOVERY_FILE_DEST
    """
    df_fra, err = run_query(conn, sql_fra)
    if err:
        results.append(make_result(chk, S_ERROR, "V$RECOVERY_FILE_DEST query failed: {e}".format(e=err)))
    else:
        if _empty(df_fra):
            results.append(make_result(chk, S_NA, "FRA not configured (V$RECOVERY_FILE_DEST empty)"))
        for row in _rows(df_fra):
            pct   = _num(_val(row, "pct_used"))
            limit = _num(_val(row, "limit_gb"))
            used  = _num(_val(row, "used_gb"))
            recl  = _num(_val(row, "reclaimable_gb"))
            files = _str(_val(row, "number_of_files"))
            s     = S_CRITICAL if pct >= FRA_CRIT_PCT else (S_WARNING if pct >= FRA_WARN_PCT else S_OK)
            results.append(make_result(
                chk, s,
                "FRA={n} Used={p}% Limit={l:.2f}GB Used={u:.2f}GB "
                "Reclaimable={r:.2f}GB Files={f}".format(
                    n = _str(_val(row, "name")),
                    p=pct, l=limit, u=used, r=recl, f=files),
                pct_used=pct, limit_gb=limit, used_gb=used,
            ))

    # Per-file-type breakdown
    sql_type = """
        SELECT FILE_TYPE,
               ROUND(PERCENT_SPACE_USED, 1) pct_used,
               ROUND(SPACE_USED/1073741824, 3) used_gb,
               NUMBER_OF_FILES
        FROM   V$RECOVERY_AREA_USAGE
        WHERE  PERCENT_SPACE_USED > 0
        ORDER  BY PERCENT_SPACE_USED DESC
    """
    df_type, err2 = run_query(conn, sql_type)
    if not err2 and not _empty(df_type):
        for row in _rows(df_type):
            pct  = _num(_val(row, "pct_used"))
            s    = S_CRITICAL if pct >= FRA_CRIT_PCT else (S_WARNING if pct >= FRA_WARN_PCT else S_OK)
            results.append(make_result(
                chk, s,
                "FRA FileType={t} Used={p}% ({u:.3f}GB) Files={f}".format(
                    t = _str(_val(row, "file_type")),
                    p=pct,
                    u = _num(_val(row, "used_gb")),
                    f = _str(_val(row, "number_of_files")),
                ),
            ))

    return results or [make_result(chk, S_NA, "FRA not configured or inaccessible")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 8 – ASM STORAGE  (V$ASM_DISKGROUP)
# ─────────────────────────────────────────────────────────────────────────────
def check_asm_storage(conn, db_cfg):
    """Check ASM disk group space and state via V$ASM_DISKGROUP."""
    chk = "ASM_STORAGE"
    sql = """
        SELECT NAME,
               STATE,
               TYPE,
               ROUND(TOTAL_MB/1024, 2)                                        total_gb,
               ROUND(FREE_MB/1024, 2)                                         free_gb,
               ROUND((TOTAL_MB - FREE_MB) / NULLIF(TOTAL_MB,0) * 100, 1)     pct_used,
               OFFLINE_DISKS,
               TOTAL_MB,
               FREE_MB
        FROM   V$ASM_DISKGROUP
        ORDER  BY NAME
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_NA,
                            "V$ASM_DISKGROUP inaccessible (requires SYSDBA or ASM privileges): {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_NA, "No ASM disk groups visible from this connection")]

    results = []
    for row in _rows(df):
        name     = _str(_val(row, "name"))
        state    = _str(_val(row, "state"))
        pct      = _num(_val(row, "pct_used"))
        tot_gb   = _num(_val(row, "total_gb"))
        free_gb  = _num(_val(row, "free_gb"))
        offline  = _num(_val(row, "offline_disks"))

        s = S_OK
        if state != "MOUNTED":
            s = S_CRITICAL
        elif offline > 0:
            s = S_CRITICAL
        elif pct >= ASM_CRIT_PCT:
            s = S_CRITICAL
        elif pct >= ASM_WARN_PCT:
            s = S_WARNING

        results.append(make_result(
            chk, s,
            "DG={n} State={st} Type={ty} Total={t:.2f}GB Free={f:.2f}GB "
            "Used={p}% OfflineDisks={od}".format(
                n  = name,
                st = state,
                ty = _str(_val(row, "type")),
                t  = tot_gb, f = free_gb, p = pct, od = int(offline),
            ),
            dg_name=name, state=state, pct_used=pct, offline_disks=int(offline),
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 9-13 – RMAN BACKUP
# ─────────────────────────────────────────────────────────────────────────────
def check_rman_backup(conn, db_cfg):
    """
    Comprehensive RMAN backup health check:
      • Last DB FULL backup         (CRITICAL if > {fc} days)
      • Last DB INCR backup         (CRITICAL if > {ic} hours)
      • Last ARCHIVELOG backup      (CRITICAL if > {ac} hours)
      • Failed RMAN jobs (7 days)
      • Oldest available backup piece
    """.format(
        fc=RMAN_FULL_CRIT_DAYS,
        ic=RMAN_INCR_CRIT_HOURS,
        ac=RMAN_ARCH_CRIT_HOURS,
    )
    chk = "RMAN_BACKUP"
    if not db_cfg.get("rman_check", True):
        return [make_result(chk, S_NA, "RMAN backup check disabled for this database")]

    results = []

    # ── Latest successful backup by INPUT_TYPE ────────────────────────────────
    sql_latest = """
        SELECT INPUT_TYPE,
               MAX(END_TIME)                              last_completion,
               ROUND((SYSDATE - MAX(END_TIME)) * 24, 2)  hours_ago,
               SUM(CASE WHEN STATUS='FAILED' THEN 1 ELSE 0 END) failed_count,
               COUNT(*)                                   total_jobs
        FROM   V$RMAN_BACKUP_JOB_DETAILS
        WHERE  START_TIME > SYSDATE - 14
        AND    STATUS IN ('COMPLETED','COMPLETED WITH WARNINGS')
        GROUP  BY INPUT_TYPE
        ORDER  BY INPUT_TYPE
    """
    df_lat, err = run_query(conn, sql_latest)
    if err:
        results.append(make_result(chk, S_ERROR,
                                   "V$RMAN_BACKUP_JOB_DETAILS query failed: {e}".format(e=err)))
        return results

    # Index results by normalised type
    backup_map = {}
    for row in _rows(df_lat):
        itype     = _str(_val(row, "input_type"))
        hours_ago = _num(_val(row, "hours_ago"), default=None)
        backup_map[itype] = hours_ago

    # Helper to get minimum hours across matching types
    def _latest_hours(*types):
        vals = [backup_map[t] for t in types if t in backup_map and backup_map[t] is not None]
        return min(vals) if vals else None

    # ── Full backup check ─────────────────────────────────────────────────────
    full_h = _latest_hours("DB FULL", "DATAFILE FULL")
    if full_h is None:
        results.append(make_result(
            chk, S_CRITICAL,
            "FULL: No completed full backup found in last 14 days",
            backup_type="FULL",
        ))
    else:
        full_days = full_h / 24.0
        s = (S_CRITICAL if full_days > RMAN_FULL_CRIT_DAYS
             else S_WARNING if full_days > RMAN_FULL_WARN_DAYS
             else S_OK)
        results.append(make_result(
            chk, s,
            "FULL: Last full backup {h:.1f}h ago ({d:.1f} days) "
            "[CRIT>{fc}d WARN>{fw}d]".format(
                h=full_h, d=full_days,
                fc=RMAN_FULL_CRIT_DAYS, fw=RMAN_FULL_WARN_DAYS),
            backup_type="FULL", hours_ago=full_h,
        ))

    # ── Incremental backup check ──────────────────────────────────────────────
    incr_h = _latest_hours("DB INCR", "DATAFILE INCR")
    if incr_h is None:
        results.append(make_result(
            chk, S_CRITICAL,
            "INCR: No completed incremental backup found in last 14 days",
            backup_type="INCR",
        ))
    else:
        s = (S_CRITICAL if incr_h > RMAN_INCR_CRIT_HOURS
             else S_WARNING if incr_h > RMAN_INCR_WARN_HOURS
             else S_OK)
        results.append(make_result(
            chk, s,
            "INCR: Last incremental backup {h:.1f}h ago "
            "[CRIT>{ic}h WARN>{iw}h]".format(
                h=incr_h,
                ic=RMAN_INCR_CRIT_HOURS, iw=RMAN_INCR_WARN_HOURS),
            backup_type="INCR", hours_ago=incr_h,
        ))

    # ── Archive log backup check ──────────────────────────────────────────────
    arch_h = _latest_hours("ARCHIVELOG")
    if arch_h is None:
        results.append(make_result(
            chk, S_CRITICAL,
            "ARCH: No archive log backup found in last 14 days",
            backup_type="ARCH",
        ))
    else:
        s = (S_CRITICAL if arch_h > RMAN_ARCH_CRIT_HOURS
             else S_WARNING if arch_h > RMAN_ARCH_WARN_HOURS
             else S_OK)
        results.append(make_result(
            chk, s,
            "ARCH: Last archive log backup {h:.2f}h ago "
            "[CRIT>{ac}h WARN>{aw}h]".format(
                h=arch_h,
                ac=RMAN_ARCH_CRIT_HOURS, aw=RMAN_ARCH_WARN_HOURS),
            backup_type="ARCH", hours_ago=arch_h,
        ))

    # ── Failed RMAN jobs (last 7 days) ────────────────────────────────────────
    sql_fail = """
        SELECT INPUT_TYPE, STATUS,
               TO_CHAR(START_TIME,'YYYY-MM-DD HH24:MI') start_time,
               TO_CHAR(END_TIME,  'YYYY-MM-DD HH24:MI') end_time,
               ROUND((END_TIME - START_TIME) * 24, 2)   duration_h
        FROM   V$RMAN_BACKUP_JOB_DETAILS
        WHERE  STATUS NOT IN ('COMPLETED','COMPLETED WITH WARNINGS','RUNNING')
        AND    START_TIME > SYSDATE - 7
        ORDER  BY START_TIME DESC
        FETCH  FIRST 10 ROWS ONLY
    """
    df_fail, err2 = run_query(conn, sql_fail)
    if err2:
        results.append(make_result(chk, S_ERROR,
                                   "RMAN failed jobs query error: {e}".format(e=err2)))
    elif not _empty(df_fail):
        for row in _rows(df_fail):
            results.append(make_result(
                chk, S_CRITICAL,
                "FAILED: Type={t} Status={s} Start={st} End={en} Duration={d}h".format(
                    t  = _str(_val(row, "input_type")),
                    s  = _str(_val(row, "status")),
                    st = _str(_val(row, "start_time")),
                    en = _str(_val(row, "end_time")),
                    d  = _num(_val(row, "duration_h")),
                ),
                backup_type="FAILED",
            ))

    # ── Oldest available backup piece ─────────────────────────────────────────
    sql_old = """
        SELECT TO_CHAR(MIN(COMPLETION_TIME),'YYYY-MM-DD HH24:MI') oldest_backup,
               ROUND(SYSDATE - MIN(COMPLETION_TIME))              age_days,
               COUNT(*)                                            available_pieces
        FROM   V$BACKUP_PIECE
        WHERE  STATUS = 'A'
    """
    df_old, err3 = run_query(conn, sql_old)
    if err3:
        results.append(make_result(chk, S_ERROR,
                                   "V$BACKUP_PIECE query failed: {e}".format(e=err3)))
    else:
        for row in _rows(df_old):
            age      = _num(_val(row, "age_days"))
            oldest   = _str(_val(row, "oldest_backup"))
            pieces   = _num(_val(row, "available_pieces"))
            if pieces == 0:
                results.append(make_result(chk, S_CRITICAL,
                                           "OLDEST: No available backup pieces found in V$BACKUP_PIECE"))
            else:
                results.append(make_result(
                    chk, S_OK,
                    "OLDEST: OldestBackup={d} Age={a:.0f}days AvailablePieces={p:.0f}".format(
                        d=oldest, a=age, p=pieces),
                    backup_type="OLDEST", age_days=age,
                ))

    return results or [make_result(chk, S_WARNING, "No RMAN backup data returned")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 14-17 – SCHEDULER JOBS
# ─────────────────────────────────────────────────────────────────────────────
_SYS_OWNER_SQL = ", ".join("'{o}'".format(o=o) for o in sorted(_SYS_OWNERS))


def check_scheduler_jobs(conn, db_cfg):
    """
    Four scheduler sub-checks in one call:
      • Stats (enabled / disabled / broken / running counts)
      • Failed jobs in last 24 h
      • Long-running scheduler jobs
      • Disabled non-system jobs
    """
    chk = "SCHEDULER"
    results = []

    # ── Stats ─────────────────────────────────────────────────────────────────
    sql_stats = """
        SELECT STATE, ENABLED, COUNT(*) cnt
        FROM   DBA_SCHEDULER_JOBS
        WHERE  OWNER NOT IN ({sys})
        GROUP  BY STATE, ENABLED
        ORDER  BY STATE
    """.format(sys=_SYS_OWNER_SQL)

    df_st, err = run_query(conn, sql_stats)
    if err:
        results.append(make_result(chk, S_ERROR, "Job stats query failed: {e}".format(e=err)))
    else:
        from collections import defaultdict
        counts = defaultdict(int)
        for row in _rows(df_st):
            state   = _str(_val(row, "state"))
            enabled = _str(_val(row, "enabled"))
            cnt     = int(_num(_val(row, "cnt")))
            counts[state] += cnt
            if enabled == "FALSE":
                counts["DISABLED"] += cnt

        stat_str = " ".join(
            "{k}={v}".format(k=k, v=v) for k, v in sorted(counts.items())
        )
        broken = counts.get("BROKEN", 0)
        s = S_CRITICAL if broken > 0 else S_OK
        results.append(make_result(
            chk, s,
            "STATS: {s}".format(s=stat_str or "No user jobs found"),
            sub_check="STATS", broken_count=broken,
        ))

    # ── Failed jobs (last 24 h) ───────────────────────────────────────────────
    sql_fail = """
        SELECT JOB_NAME, OWNER, STATUS,
               TO_CHAR(LOG_DATE,'YYYY-MM-DD HH24:MI') log_date,
               SUBSTR(ADDITIONAL_INFO, 1, 150)         error_info
        FROM   DBA_SCHEDULER_JOB_LOG
        WHERE  STATUS = 'FAILED'
        AND    LOG_DATE > SYSTIMESTAMP - INTERVAL '{h}' HOUR
        AND    OWNER NOT IN ({sys})
        ORDER  BY LOG_DATE DESC
        FETCH  FIRST 20 ROWS ONLY
    """.format(h=24, sys=_SYS_OWNER_SQL)

    df_fail, err2 = run_query(conn, sql_fail)
    if err2:
        results.append(make_result(chk, S_ERROR,
                                   "Failed jobs query failed: {e}".format(e=err2)))
    elif _empty(df_fail):
        results.append(make_result(chk, S_OK, "FAILED_JOBS: No failed jobs in last 24h",
                                   sub_check="FAILED_JOBS"))
    else:
        for row in _rows(df_fail):
            results.append(make_result(
                chk, S_CRITICAL,
                "FAILED_JOB: {o}.{j} at {t} | {e}".format(
                    o = _str(_val(row, "owner")),
                    j = _str(_val(row, "job_name")),
                    t = _str(_val(row, "log_date")),
                    e = _str(_val(row, "error_info")),
                ),
                sub_check="FAILED_JOBS",
            ))

    # ── Long-running jobs ─────────────────────────────────────────────────────
    sql_long = """
        SELECT JOB_NAME, OWNER,
               ROUND(
                 (EXTRACT(HOUR   FROM ELAPSED_TIME) * 3600 +
                  EXTRACT(MINUTE FROM ELAPSED_TIME) * 60   +
                  EXTRACT(SECOND FROM ELAPSED_TIME)) / 3600, 2
               ) elapsed_h,
               SESSION_ID,
               RUNNING_INSTANCE
        FROM   DBA_SCHEDULER_RUNNING_JOBS
        WHERE  OWNER NOT IN ({sys})
        ORDER  BY elapsed_h DESC
    """.format(sys=_SYS_OWNER_SQL)

    df_long, err3 = run_query(conn, sql_long)
    if err3:
        results.append(make_result(chk, S_ERROR,
                                   "Running jobs query failed: {e}".format(e=err3)))
    else:
        for row in _rows(df_long):
            elapsed = _num(_val(row, "elapsed_h"))
            s = (S_CRITICAL if elapsed >= LONG_JOB_CRIT_H
                 else S_WARNING if elapsed >= LONG_JOB_WARN_H
                 else S_OK)
            if s != S_OK:
                results.append(make_result(
                    chk, s,
                    "LONG_JOB: {o}.{j} running {e:.2f}h SID={sid} Inst={i}".format(
                        o   = _str(_val(row, "owner")),
                        j   = _str(_val(row, "job_name")),
                        e   = elapsed,
                        sid = _str(_val(row, "session_id")),
                        i   = _str(_val(row, "running_instance")),
                    ),
                    sub_check="LONG_JOBS", elapsed_h=elapsed,
                ))

    # ── Disabled jobs ─────────────────────────────────────────────────────────
    sql_dis = """
        SELECT JOB_NAME, OWNER, JOB_TYPE, STATE,
               TO_CHAR(LAST_START_DATE,'YYYY-MM-DD HH24:MI') last_run
        FROM   DBA_SCHEDULER_JOBS
        WHERE  ENABLED = 'FALSE'
        AND    OWNER NOT IN ({sys})
        ORDER  BY OWNER, JOB_NAME
        FETCH  FIRST 30 ROWS ONLY
    """.format(sys=_SYS_OWNER_SQL)

    df_dis, err4 = run_query(conn, sql_dis)
    if err4:
        results.append(make_result(chk, S_ERROR,
                                   "Disabled jobs query failed: {e}".format(e=err4)))
    elif _empty(df_dis):
        results.append(make_result(chk, S_OK, "DISABLED_JOBS: No disabled user jobs",
                                   sub_check="DISABLED_JOBS"))
    else:
        for row in _rows(df_dis):
            results.append(make_result(
                chk, S_WARNING,
                "DISABLED_JOB: {o}.{j} Type={t} State={s} LastRun={lr}".format(
                    o  = _str(_val(row, "owner")),
                    j  = _str(_val(row, "job_name")),
                    t  = _str(_val(row, "job_type")),
                    s  = _str(_val(row, "state")),
                    lr = _str(_val(row, "last_run")),
                ),
                sub_check="DISABLED_JOBS",
            ))

    return results or [make_result(chk, S_OK, "Scheduler check complete – no issues")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 18 – INVALID OBJECTS
# ─────────────────────────────────────────────────────────────────────────────
def check_invalid_objects(conn, db_cfg):
    """Count and list non-system invalid objects by owner and type."""
    chk = "INVALID_OBJECTS"

    # Summary by owner + type
    sql_sum = """
        SELECT OWNER, OBJECT_TYPE, COUNT(*) cnt
        FROM   DBA_OBJECTS
        WHERE  STATUS   = 'INVALID'
        AND    OWNER NOT IN ({sys})
        GROUP  BY OWNER, OBJECT_TYPE
        ORDER  BY OWNER, OBJECT_TYPE
    """.format(sys=_SYS_OWNER_SQL)

    df, err = run_query(conn, sql_sum)
    if err:
        return [make_result(chk, S_ERROR, "DBA_OBJECTS query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_OK, "No invalid objects found in user schemas")]

    results = []
    total = 0
    for row in _rows(df):
        cnt   = int(_num(_val(row, "cnt")))
        total += cnt
        results.append(make_result(
            chk, S_WARNING,
            "INVALID: Owner={o} Type={t} Count={c}".format(
                o = _str(_val(row, "owner")),
                t = _str(_val(row, "object_type")),
                c = cnt,
            ),
            owner=_str(_val(row, "owner")), object_type=_str(_val(row, "object_type")), count=cnt,
        ))

    # Prepend a summary row
    results.insert(0, make_result(
        chk, S_WARNING,
        "SUMMARY: Total invalid objects = {t} across {s} owner/type combinations".format(
            t=total, s=len(results)),
        sub_check="SUMMARY", total_invalid=total,
    ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 19 – BLOCKING SESSIONS
# ─────────────────────────────────────────────────────────────────────────────
def check_blocking_sessions(conn, db_cfg):
    """Detect sessions blocking others for more than BLOCKING_WARN_SECS."""
    chk = "BLOCKING_SESSIONS"
    sql = """
        SELECT s.SID                                blocked_sid,
               s.SERIAL#                            blocked_serial,
               NVL(s.USERNAME,'(background)')       blocked_user,
               s.MACHINE                            blocked_machine,
               s.BLOCKING_SESSION                   blocker_sid,
               NVL(bs.USERNAME,'(background)')      blocker_user,
               bs.MACHINE                           blocker_machine,
               s.WAIT_CLASS,
               s.EVENT,
               s.SECONDS_IN_WAIT                   wait_secs,
               s.ROW_WAIT_OBJ#                     obj_id
        FROM   V$SESSION s
        LEFT   JOIN V$SESSION bs ON s.BLOCKING_SESSION = bs.SID
        WHERE  s.BLOCKING_SESSION IS NOT NULL
        AND    s.BLOCKING_SESSION_STATUS = 'VALID'
        AND    s.SECONDS_IN_WAIT > {w}
        ORDER  BY s.SECONDS_IN_WAIT DESC
        FETCH  FIRST 20 ROWS ONLY
    """.format(w=60)

    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "V$SESSION query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_OK, "No blocking sessions detected (> 60s)")]

    results = []
    for row in _rows(df):
        wait_s = _num(_val(row, "wait_secs"))
        s = (S_CRITICAL if wait_s >= BLOCKING_CRIT_SECS
             else S_WARNING if wait_s >= BLOCKING_WARN_SECS
             else S_OK)
        results.append(make_result(
            chk, s,
            "BLOCKED SID={bsid}({bu}@{bm}) by SID={ksid}({ku}@{km}) "
            "WaitEvent={ev} WaitClass={wc} WaitSecs={ws:.0f}".format(
                bsid = _str(_val(row, "blocked_sid")),
                bu   = _str(_val(row, "blocked_user")),
                bm   = _str(_val(row, "blocked_machine")),
                ksid = _str(_val(row, "blocker_sid")),
                ku   = _str(_val(row, "blocker_user")),
                km   = _str(_val(row, "blocker_machine")),
                ev   = _str(_val(row, "event")),
                wc   = _str(_val(row, "wait_class")),
                ws   = wait_s,
            ),
            wait_secs=wait_s,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 20 – LONG RUNNING SESSIONS
# ─────────────────────────────────────────────────────────────────────────────
def check_long_sessions(conn, db_cfg):
    """Detect user sessions with active SQL running longer than threshold."""
    chk = "LONG_SESSIONS"
    sql = """
        SELECT s.SID,
               s.SERIAL#,
               NVL(s.USERNAME,'(bg)')                 username,
               s.STATUS,
               s.MACHINE,
               s.MODULE,
               s.PROGRAM,
               s.EVENT,
               ROUND(q.ELAPSED_TIME / 3600000000, 2)  elapsed_h,
               SUBSTR(q.SQL_TEXT, 1, 120)              sql_text
        FROM   V$SESSION s
        JOIN   V$SQL q ON s.SQL_ID = q.SQL_ID
                      AND s.SQL_CHILD_NUMBER = q.CHILD_NUMBER
        WHERE  s.STATUS   = 'ACTIVE'
        AND    s.USERNAME IS NOT NULL
        AND    s.USERNAME NOT IN ({sys})
        AND    q.ELAPSED_TIME / 3600000000 > {warn}
        ORDER  BY q.ELAPSED_TIME DESC
        FETCH  FIRST 10 ROWS ONLY
    """.format(sys=_SYS_OWNER_SQL, warn=LONG_SESSION_WARN_H)

    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "Long session query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(
            chk, S_OK,
            "No active sessions running longer than {h}h".format(h=LONG_SESSION_WARN_H),
        )]

    results = []
    for row in _rows(df):
        elapsed = _num(_val(row, "elapsed_h"))
        s = (S_CRITICAL if elapsed >= LONG_SESSION_CRIT_H
             else S_WARNING if elapsed >= LONG_SESSION_WARN_H
             else S_OK)
        results.append(make_result(
            chk, s,
            "SID={sid} User={u} Machine={m} Module={mo} Event={ev} "
            "Elapsed={e:.2f}h SQL=[{sql}]".format(
                sid = _str(_val(row, "sid")),
                u   = _str(_val(row, "username")),
                m   = _str(_val(row, "machine")),
                mo  = _str(_val(row, "module")),
                ev  = _str(_val(row, "event")),
                e   = elapsed,
                sql = _str(_val(row, "sql_text")),
            ),
            elapsed_h=elapsed,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 21 – REDO LOG STATUS
# ─────────────────────────────────────────────────────────────────────────────
def check_redo_logs(conn, db_cfg):
    """Check redo log group status and alert on high log-switch frequency."""
    chk = "REDO_LOGS"
    results = []

    # Redo log groups
    sql_grp = """
        SELECT GROUP#, MEMBERS, STATUS, ARCHIVED,
               ROUND(BYTES/1048576) size_mb,
               TO_CHAR(FIRST_TIME,'YYYY-MM-DD HH24:MI') first_time
        FROM   V$LOG
        ORDER  BY GROUP#
    """
    df_grp, err = run_query(conn, sql_grp)
    if err:
        results.append(make_result(chk, S_ERROR, "V$LOG query failed: {e}".format(e=err)))
    else:
        for row in _rows(df_grp):
            status   = _str(_val(row, "status"))
            archived = _str(_val(row, "archived"))
            grp      = _str(_val(row, "group#"))
            members  = _str(_val(row, "members"))
            size_mb  = _num(_val(row, "size_mb"))

            # ACTIVE (not current, still needed for crash recovery) and not archived → WARNING
            s = S_OK
            if status == "ACTIVE" and archived == "NO":
                s = S_WARNING
            elif status not in ("CURRENT", "ACTIVE", "INACTIVE"):
                s = S_CRITICAL

            results.append(make_result(
                chk, s,
                "Group={g} Members={m} Status={st} Archived={ar} "
                "Size={sz:.0f}MB FirstTime={ft}".format(
                    g  = grp,
                    m  = members,
                    st = status,
                    ar = archived,
                    sz = size_mb,
                    ft = _str(_val(row, "first_time")),
                ),
                group=grp, status=status, archived=archived,
            ))

    # Log switch frequency (last 24 h) – excessive switching → WARNING
    sql_sw = """
        SELECT TRUNC(FIRST_TIME,'HH24') hour_mark,
               COUNT(*)                 switches
        FROM   V$LOG_HISTORY
        WHERE  FIRST_TIME > SYSDATE - 1
        GROUP  BY TRUNC(FIRST_TIME,'HH24')
        ORDER  BY 1 DESC
        FETCH  FIRST 5 ROWS ONLY
    """
    df_sw, err2 = run_query(conn, sql_sw)
    if not err2 and not _empty(df_sw):
        for row in _rows(df_sw):
            sw   = int(_num(_val(row, "switches")))
            hour = _str(_val(row, "hour_mark"))
            # > 6 switches/hour is generally unusual for production
            s = S_CRITICAL if sw > 12 else (S_WARNING if sw > 6 else S_OK)
            if s != S_OK:
                results.append(make_result(
                    chk, s,
                    "LOG_SWITCH: {sw} switches at hour {h} "
                    "(>6/h=WARNING >12/h=CRITICAL)".format(sw=sw, h=hour),
                    sub_check="LOG_SWITCH", switches=sw, hour=hour,
                ))

    return results or [make_result(chk, S_OK, "Redo log check complete – no issues")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 22 – ARCHIVE DESTINATIONS
# ─────────────────────────────────────────────────────────────────────────────
def check_archive_dest(conn, db_cfg):
    """Check archive destination status and error messages."""
    chk = "ARCHIVE_DEST"
    sql = """
        SELECT DEST_ID, TARGET, ARCHIVER, STATUS,
               DESTINATION,
               SUBSTR(NVL(ERROR,'OK'),1,120) dest_error,
               SCHEDULE
        FROM   V$ARCHIVE_DEST
        WHERE  STATUS IN ('VALID','ERROR','INACTIVE')
        AND    TARGET  = 'PRIMARY'
        ORDER  BY DEST_ID
    """
    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "V$ARCHIVE_DEST query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_WARNING, "No archive destinations found")]

    results = []
    for row in _rows(df):
        status   = _str(_val(row, "status"))
        arch_err = _str(_val(row, "dest_error"))
        dest     = _str(_val(row, "destination"))

        if status == "ERROR":
            s = S_CRITICAL
        elif status == "INACTIVE":
            s = S_WARNING
        else:
            s = S_OK

        results.append(make_result(
            chk, s,
            "DestID={d} Target={tgt} Status={st} Dest={dest} Error={e}".format(
                d    = _str(_val(row, "dest_id")),
                tgt  = _str(_val(row, "target")),
                st   = status,
                dest = dest,
                e    = arch_err,
            ),
            dest_id=_str(_val(row, "dest_id")), status=status,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 23 – DATA GUARD STATUS
# ─────────────────────────────────────────────────────────────────────────────
def check_dataguard(conn, db_cfg):
    """Check Data Guard role, protection mode, and apply/transport lag."""
    chk = "DATA_GUARD"
    if not db_cfg.get("dg_check", False):
        return [make_result(chk, S_NA, "Data Guard check disabled for this database")]

    sql_db = """
        SELECT DATABASE_ROLE, PROTECTION_MODE, PROTECTION_LEVEL,
               SWITCHOVER_STATUS, DATAGUARD_BROKER, GUARD_STATUS
        FROM   V$DATABASE
    """
    df_db, err = run_query(conn, sql_db)
    if err:
        return [make_result(chk, S_ERROR, "V$DATABASE DG query failed: {e}".format(e=err))]

    results = []
    for row in _rows(df_db):
        role   = _str(_val(row, "database_role"))
        sw_sts = _str(_val(row, "switchover_status"))
        prot   = _str(_val(row, "protection_mode"))

        # Switchover_status = SESSIONS ACTIVE or NOT ALLOWED may indicate issues
        s = S_WARNING if sw_sts in ("NOT ALLOWED", "FAILED DESTINATION") else S_OK

        results.append(make_result(
            chk, s,
            "Role={r} ProtMode={pm} ProtLevel={pl} "
            "SwitchoverStatus={ss} Broker={br} Guard={g}".format(
                r  = role,
                pm = prot,
                pl = _str(_val(row, "protection_level")),
                ss = sw_sts,
                br = _str(_val(row, "dataguard_broker")),
                g  = _str(_val(row, "guard_status")),
            ),
            db_role=role,
        ))

    # Data Guard statistics (apply lag, transport lag)
    sql_lag = """
        SELECT NAME, VALUE, UNIT,
               TO_CHAR(TIME_COMPUTED,'YYYY-MM-DD HH24:MI') computed_at
        FROM   V$DATAGUARD_STATS
        WHERE  NAME IN ('transport lag','apply lag','apply finish time',
                        'estimated startup time')
    """
    df_lag, err2 = run_query(conn, sql_lag)
    if not err2 and not _empty(df_lag):
        for row in _rows(df_lag):
            stat_name = _str(_val(row, "name"))
            val       = _str(_val(row, "value"))
            unit      = _str(_val(row, "unit"))

            # Parse lag: if > 30 min → WARNING; > 60 min → CRITICAL
            s = S_OK
            lag_m = None
            m = re.match(r"(\d+)\s*day.*?(\d+):(\d+):(\d+)", str(val))
            if not m:
                m = re.match(r"(\d+):(\d+):(\d+)", str(val))
                if m:
                    lag_m = int(m.group(1)) * 60 + int(m.group(2))
            elif m:
                lag_m = int(m.group(1)) * 1440 + int(m.group(2)) * 60 + int(m.group(3))

            if "lag" in stat_name.lower() and lag_m is not None:
                if lag_m >= 60:
                    s = S_CRITICAL
                elif lag_m >= 30:
                    s = S_WARNING

            results.append(make_result(
                chk, s,
                "DG Stat: {n}={v} {u} (computed {t})".format(
                    n = stat_name,
                    v = val,
                    u = unit,
                    t = _str(_val(row, "computed_at")),
                ),
                dg_stat=stat_name, lag_minutes=lag_m,
            ))

    return results or [make_result(chk, S_NA, "No Data Guard configuration found")]

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 24 – ALERT LOG ERRORS  (via V$DIAG_ALERT_EXT)
# ─────────────────────────────────────────────────────────────────────────────
def check_alert_log_sql(conn, db_cfg):
    """
    Query V$DIAG_ALERT_EXT for ORA- errors in the last ALERT_LOG_HOURS hours.
    Requires SELECT ANY DICTIONARY or SYSDBA; degrades gracefully if denied.
    """
    chk = "ALERT_LOG_SQL"
    sql = """
        SELECT TO_CHAR(ORIGINATING_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS') ts,
               SUBSTR(MESSAGE_TEXT, 1, 200)                            msg
        FROM   V$DIAG_ALERT_EXT
        WHERE  ORIGINATING_TIMESTAMP > SYSTIMESTAMP - INTERVAL '{h}' HOUR
        AND   (MESSAGE_TEXT LIKE 'ORA-%' OR MESSAGE_TEXT LIKE '%ORA-%')
        AND    MESSAGE_TEXT NOT LIKE '%normal%'
        ORDER  BY ORIGINATING_TIMESTAMP DESC
        FETCH  FIRST 30 ROWS ONLY
    """.format(h=ALERT_LOG_HOURS)

    df, err = run_query(conn, sql)
    if err:
        return [make_result(
            chk, S_NA,
            "V$DIAG_ALERT_EXT inaccessible (needs SELECT ANY DICTIONARY): {e}".format(e=err),
        )]
    if _empty(df):
        return [make_result(
            chk, S_OK,
            "No ORA- errors in alert log in last {h}h".format(h=ALERT_LOG_HOURS),
        )]

    # Classify by ORA- code
    critical_prefix = {
        "ORA-00600", "ORA-07445", "ORA-04031", "ORA-01578",
        "ORA-00257", "ORA-16038", "ORA-15130", "ORA-15050",
    }
    results = []
    for row in _rows(df):
        msg  = _str(_val(row, "msg"))
        ts   = _str(_val(row, "ts"))
        ora_codes = re.findall(r"ORA-\d+", msg)
        s = S_CRITICAL if any(c in critical_prefix for c in ora_codes) else S_WARNING
        results.append(make_result(
            chk, s,
            "AlertLog [{ts}] {msg}".format(ts=ts, msg=msg[:160]),
            ora_codes=ora_codes,
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 25 – TOP WAIT EVENTS
# ─────────────────────────────────────────────────────────────────────────────
def check_top_waits(conn, db_cfg):
    """Report the top non-idle system wait events from V$SYSTEM_EVENT."""
    chk = "TOP_WAIT_EVENTS"
    sql = """
        SELECT EVENT,
               TOTAL_WAITS,
               TOTAL_TIMEOUTS,
               ROUND(TIME_WAITED_MICRO / 1000000, 2)  time_waited_sec,
               ROUND(AVERAGE_WAIT / 100, 3)            avg_wait_ms,
               WAIT_CLASS
        FROM   V$SYSTEM_EVENT
        WHERE  WAIT_CLASS NOT IN ('Idle','Background')
        ORDER  BY TIME_WAITED_MICRO DESC
        FETCH  FIRST {n} ROWS ONLY
    """.format(n=WAIT_EVENT_TOP_N)

    df, err = run_query(conn, sql)
    if err:
        return [make_result(chk, S_ERROR, "V$SYSTEM_EVENT query failed: {e}".format(e=err))]
    if _empty(df):
        return [make_result(chk, S_OK, "No significant wait events")]

    results = []
    for row in _rows(df):
        results.append(make_result(
            chk, S_OK,
            "Event=[{ev}] Class={cls} TotalWaits={tw} "
            "TotalTimeSec={tt:.2f} AvgWaitMs={aw:.3f} Timeouts={to}".format(
                ev  = _str(_val(row, "event")),
                cls = _str(_val(row, "wait_class")),
                tw  = int(_num(_val(row, "total_waits"))),
                tt  = _num(_val(row, "time_waited_sec")),
                aw  = _num(_val(row, "avg_wait_ms")),
                to  = int(_num(_val(row, "total_timeouts"))),
            ),
            event=_str(_val(row, "event")),
        ))
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHECK 26 – MEMORY  (SGA + PGA)
# ─────────────────────────────────────────────────────────────────────────────
def check_memory(conn, db_cfg):
    """Report SGA component sizes and PGA statistics."""
    chk = "MEMORY"
    results = []

    # SGA
    sql_sga = """
        SELECT NAME, ROUND(BYTES/1073741824, 3) size_gb
        FROM   V$SGAINFO
        WHERE  NAME IN (
            'Total SGA Size','Buffer Cache Size','Shared Pool Size',
            'Large Pool Size','Java Pool Size','Streams Pool Size',
            'Shared IO Pool Size','Redo Buffers','Fixed SGA Size'
        )
        ORDER  BY BYTES DESC
    """
    df_sga, err = run_query(conn, sql_sga)
    if err:
        results.append(make_result(chk, S_ERROR, "V$SGAINFO query failed: {e}".format(e=err)))
    else:
        sga_parts = []
        for row in _rows(df_sga):
            sga_parts.append("{n}={v:.3f}GB".format(
                n = _str(_val(row, "name")),
                v = _num(_val(row, "size_gb")),
            ))
        if sga_parts:
            results.append(make_result(
                chk, S_OK,
                "SGA: " + " | ".join(sga_parts),
                sub_check="SGA",
            ))

    # PGA
    sql_pga = """
        SELECT NAME, ROUND(VALUE/1073741824, 3) size_gb
        FROM   V$PGASTAT
        WHERE  NAME IN (
            'total PGA allocated',
            'maximum PGA allocated',
            'total PGA used for auto workareas',
            'over allocation count'
        )
        ORDER  BY NAME
    """
    df_pga, err2 = run_query(conn, sql_pga)
    if err2:
        results.append(make_result(chk, S_ERROR, "V$PGASTAT query failed: {e}".format(e=err2)))
    else:
        over_alloc = 0
        pga_parts  = []
        for row in _rows(df_pga):
            name = _str(_val(row, "name"))
            val  = _num(_val(row, "size_gb"))
            if "over allocation" in name.lower():
                over_alloc = val
            else:
                pga_parts.append("{n}={v:.3f}GB".format(n=name, v=val))

        s = S_WARNING if over_alloc > 0 else S_OK
        if pga_parts:
            results.append(make_result(
                chk, s,
                "PGA: {parts} OverAllocCount={oa}".format(
                    parts = " | ".join(pga_parts),
                    oa    = int(over_alloc),
                ),
                sub_check="PGA", over_alloc=int(over_alloc),
            ))

    return results or [make_result(chk, S_ERROR, "No SGA/PGA data returned")]

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT GENERATION  (same structure as HealthCheck_V5)
# ─────────────────────────────────────────────────────────────────────────────
_WIDTH = 130
_SEP   = "=" * _WIDTH
_DSEP  = "-" * _WIDTH


def _log(buf, text=""):
    """Append to line buffer and echo to stdout."""
    buf.append(str(text))
    print(str(text))


def _section(buf, title, check_results):
    """Render one labelled check-result section."""
    _log(buf)
    _log(buf, "  [{t}]".format(t=title.upper()))
    if not check_results:
        _log(buf, "    (no data)")
        return
    for r in check_results:
        if isinstance(r, dict):
            _log(buf, "    [{s:^8}] {d}".format(
                s = r.get("status", "?"),
                d = r.get("details", ""),
            ))
        else:
            _log(buf, "    {0}".format(r))


def generate_report_and_save(all_reports, error_log):
    """
    Write a detailed per-database report and a WARNING/CRITICAL summary table.
    Saved to:  OracleDB_HealthCheck_V1_<YYYYMMDD_HHMMSS>.txt
    """
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "OracleDB_HealthCheck_V1_{ts}.txt".format(ts=ts)
    buf      = []

    def log(text=""):
        _log(buf, text)

    # ── Header ────────────────────────────────────────────────────────────────
    log(_SEP)
    log("  ORACLE DATABASE HEALTH CHECK REPORT  –  V1")
    log("  Generated : {dt}".format(dt=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    log("  Driver    : {d}   Pandas: {p}".format(d=DRIVER or "NONE", p=HAS_PANDAS))
    log(_SEP)

    # ── Per-database detail ───────────────────────────────────────────────────
    _ALL_SECTION_KEYS = (
        "connectivity", "db_info", "instances", "pdbs",
        "tablespace", "undo", "fra", "asm",
        "rman_backup",
        "scheduler", "invalid_objects",
        "blocking_sessions", "long_sessions",
        "redo_logs", "archive_dest", "dataguard",
        "alert_log_sql", "top_waits", "memory",
    )

    for rpt in all_reports:
        db_name = rpt["name"]
        log()
        log(_SEP)
        log("  DATABASE : {n}   SCAN : {s}   Service : {svc}   Port : {p}   CDB : {c}".format(
            n   = db_name,
            s   = rpt.get("scan_name", "?"),
            svc = rpt.get("service_name", "?"),
            p   = rpt.get("port", "?"),
            c   = "YES" if rpt.get("is_cdb") else "NO",
        ))
        log(_SEP)

        # Inline DB-info block
        db_info_list = rpt.get("db_info", [])
        if db_info_list and isinstance(db_info_list[0], dict):
            r0 = db_info_list[0]
            log("  {:<35} {}".format("DB Name / Unique Name:",
                "{n} / {u}".format(
                    n=r0.get("db_name",      "?"),
                    u=r0.get("db_unique_name","?"),
                )))
            log("  {:<35} {}".format("Role / Open Mode:",
                "{r} / {m}".format(r=r0.get("db_role","?"), m=r0.get("open_mode","?"))))
            log("  {:<35} {}".format("Version:", r0.get("version","?")))
            log("  {:<35} {}".format("Host Name:", r0.get("host","?")))
            log("  {:<35} {:.1f}h".format("Uptime:", _num(r0.get("uptime_h"))))
            log("  {:<35} {}".format("RAC:", "YES" if r0.get("is_rac") else "NO"))

        _section(buf, "Connectivity",           rpt.get("connectivity",      []))
        _section(buf, "Instance / Node Status", rpt.get("instances",         []))
        _section(buf, "PDB Status",             rpt.get("pdbs",              []))
        _section(buf, "Tablespace Usage",        rpt.get("tablespace",        []))
        _section(buf, "Undo Usage",              rpt.get("undo",              []))
        _section(buf, "Fast Recovery Area",      rpt.get("fra",               []))
        _section(buf, "ASM Storage",             rpt.get("asm",               []))
        _section(buf, "RMAN Backup",             rpt.get("rman_backup",       []))
        _section(buf, "Scheduler Jobs",          rpt.get("scheduler",         []))
        _section(buf, "Invalid Objects",         rpt.get("invalid_objects",   []))
        _section(buf, "Blocking Sessions",       rpt.get("blocking_sessions", []))
        _section(buf, "Long Running Sessions",   rpt.get("long_sessions",     []))
        _section(buf, "Redo Logs",               rpt.get("redo_logs",         []))
        _section(buf, "Archive Destinations",    rpt.get("archive_dest",      []))
        _section(buf, "Data Guard",              rpt.get("dataguard",         []))
        _section(buf, "Alert Log (SQL)",         rpt.get("alert_log_sql",     []))
        _section(buf, "Top Wait Events",         rpt.get("top_waits",         []))
        _section(buf, "SGA / PGA Memory",        rpt.get("memory",            []))

    # ── Connection / processing errors ────────────────────────────────────────
    if error_log:
        log()
        log(_SEP)
        log("  CONNECTION & PROCESSING ERRORS")
        log(_DSEP)
        for e in error_log:
            log("  * {0}".format(e))

    # ── Executive Summary  –  WARNING / CRITICAL only ─────────────────────────
    log()
    log(_SEP)
    log("  EXECUTIVE SUMMARY  –  CRITICAL / WARNING ITEMS  (OK / N/A omitted)")
    log(_SEP)
    col_db  = 18
    col_chk = 26
    col_st  = 12
    col_det = _WIDTH - col_db - col_chk - col_st - 4
    log("{db:<{cdb}} {chk:<{cc}} {st:<{cs}} {det}".format(
        db="Database", chk="Check", st="Status", det="Details",
        cdb=col_db, cc=col_chk, cs=col_st,
    ))
    log(_DSEP)

    has_issues = False
    for rpt in all_reports:
        db_name = rpt["name"]
        for sk in _ALL_SECTION_KEYS:
            for res in rpt.get(sk, []):
                if not isinstance(res, dict):
                    continue
                st = res.get("status", S_OK)
                if st not in (S_WARNING, S_CRITICAL, S_ERROR):
                    continue
                has_issues = True
                det = res.get("details", "")
                if len(det) > col_det:
                    det = det[:col_det - 3] + "..."
                log("{db:<{cdb}} {chk:<{cc}} {st:<{cs}} {det}".format(
                    db  = db_name,
                    chk = res.get("check_name", "UNKNOWN"),
                    st  = st,
                    det = det,
                    cdb = col_db, cc = col_chk, cs = col_st,
                ))

    if not has_issues:
        log("  All checks passed – no WARNING or CRITICAL items found.")

    log()
    log(_SEP)
    log("  Health check complete.")
    log("  Report saved to : {f}".format(f=os.path.abspath(filename)))
    log(_SEP)

    # ── Write file ─────────────────────────────────────────────────────────────
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write("\n".join(buf))
    except TypeError:
        with open(filename, "w") as fh:
            fh.write("\n".join(buf))

    return filename

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    if oracledb is None:
        print("FATAL: No Oracle driver found. Install python-oracledb:  pip install oracledb")
        sys.exit(1)
    if not DATABASES:
        print("No databases configured. Edit the DATABASES list and retry.")
        return

    all_reports = []
    all_errors  = []

    print(_SEP)
    print("  Oracle Database Health Check  –  V1")
    print("  Driver : {d}   Pandas : {p}".format(d=DRIVER, p=HAS_PANDAS))
    print("  Start  : {dt}".format(dt=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print(_SEP)

    for db_cfg in DATABASES:
        db_name = db_cfg["name"]
        conn    = None

        try:
            # ── Connect ───────────────────────────────────────────────────────
            print("\nConnecting to {n} ({scan}:{port}/{svc}) as '{u}'...".format(
                n    = db_name,
                scan = db_cfg["scan_name"],
                port = db_cfg.get("port", 1521),
                svc  = db_cfg["service_name"],
                u    = db_cfg["username"],
            ))
            conn, conn_err = connect_db(db_cfg)

            if conn_err:
                msg = "{n}: {e}".format(n=db_name, e=conn_err)
                all_errors.append(msg)
                print("  FAILED: {e}".format(e=conn_err))
                # Still record a minimal report so the summary shows CRITICAL
                all_reports.append({
                    "name":         db_name,
                    "scan_name":    db_cfg["scan_name"],
                    "service_name": db_cfg["service_name"],
                    "port":         db_cfg.get("port", 1521),
                    "is_cdb":       db_cfg.get("is_cdb", False),
                    "connectivity": [make_result(
                        "CONNECTIVITY", S_CRITICAL,
                        "Cannot connect: {e}".format(e=conn_err),
                    )],
                })
                continue

            print("  Connected OK")

            # ── Run all checks ────────────────────────────────────────────────
            rpt = {
                "name":         db_name,
                "scan_name":    db_cfg["scan_name"],
                "service_name": db_cfg["service_name"],
                "port":         db_cfg.get("port", 1521),
                "is_cdb":       db_cfg.get("is_cdb", False),
            }

            rpt["connectivity"]      = check_connectivity(conn, db_cfg)
            rpt["db_info"]           = check_db_info(conn, db_cfg)
            rpt["instances"]         = check_instance_nodes(conn, db_cfg)
            rpt["pdbs"]              = check_pdb_status(conn, db_cfg)
            rpt["tablespace"]        = check_tablespace(conn, db_cfg)
            rpt["undo"]              = check_undo(conn, db_cfg)
            rpt["fra"]               = check_fra(conn, db_cfg)
            rpt["asm"]               = check_asm_storage(conn, db_cfg)
            rpt["rman_backup"]       = check_rman_backup(conn, db_cfg)
            rpt["scheduler"]         = check_scheduler_jobs(conn, db_cfg)
            rpt["invalid_objects"]   = check_invalid_objects(conn, db_cfg)
            rpt["blocking_sessions"] = check_blocking_sessions(conn, db_cfg)
            rpt["long_sessions"]     = check_long_sessions(conn, db_cfg)
            rpt["redo_logs"]         = check_redo_logs(conn, db_cfg)
            rpt["archive_dest"]      = check_archive_dest(conn, db_cfg)
            rpt["dataguard"]         = check_dataguard(conn, db_cfg)
            rpt["alert_log_sql"]     = check_alert_log_sql(conn, db_cfg)
            rpt["top_waits"]         = check_top_waits(conn, db_cfg)
            rpt["memory"]            = check_memory(conn, db_cfg)

            all_reports.append(rpt)
            print("  All {n} checks complete for {db}.".format(
                n=len([k for k in rpt if k not in ("name","scan_name","service_name","port","is_cdb")]),
                db=db_name,
            ))

        except Exception as exc:
            msg = "{n}: Unexpected error – {e}".format(n=db_name, e=exc)
            all_errors.append(msg)
            print("  ERROR: {e}".format(e=exc))

        finally:
            _close_conn(conn)

    generate_report_and_save(all_reports, all_errors)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Fatal error: {e}".format(e=exc))
        sys.exit(1)
