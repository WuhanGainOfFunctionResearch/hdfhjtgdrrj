#!/usr/bin/env python3
"""NetWatch - a small GlassWire-style network monitor.

Backend: samples per-process connections + interface throughput with psutil,
stores history/labels in SQLite, serves a JSON API and the static HTML UI.
Only the standard library and psutil are needed.

    pip install -r requirements.txt
    python server.py            # http://127.0.0.1:8765
    python server.py --demo     # synthetic data, no privileges needed
"""
import argparse, atexit, json, re, signal, sys, os, random, socket, sqlite3, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import psutil
import capture
import inventory
import protect

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "netwatch.db")
SAMPLE_SECS = 2
TRAFFIC_KEEP = 3600  # seconds of throughput history kept in memory

db_lock = threading.Lock()
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db.executescript("""
CREATE TABLE IF NOT EXISTS connections(
  key TEXT PRIMARY KEY, process TEXT, exe TEXT, pid INTEGER, proto TEXT,
  laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER, status TEXT,
  first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 1, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS labels(
  kind TEXT, target TEXT, label TEXT DEFAULT '', color TEXT DEFAULT '',
  policy TEXT DEFAULT 'none', note TEXT DEFAULT '',
  PRIMARY KEY(kind, target));           -- kind: app | host
CREATE TABLE IF NOT EXISTS exe_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, ts REAL, user TEXT, pid INTEGER);
CREATE INDEX IF NOT EXISTS exe_runs_path ON exe_runs(path, ts);
CREATE TABLE IF NOT EXISTS executables(
  path TEXT PRIMARY KEY, filename TEXT, first_run REAL, last_run REAL, runs INTEGER DEFAULT 1,
  publisher TEXT DEFAULT '', signed INTEGER, verified_by TEXT DEFAULT '', sha256 TEXT DEFAULT '',
  user TEXT DEFAULT '', baseline INTEGER DEFAULT 0, status TEXT DEFAULT 'pending',
  risky INTEGER DEFAULT 0, mtime REAL, modified INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, proto TEXT DEFAULT 'any', port TEXT DEFAULT '',
  direction TEXT DEFAULT 'both', path TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
  note TEXT DEFAULT '', created REAL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, subject TEXT,
  detail TEXT, ack INTEGER DEFAULT 0);
""")

def migrate():
    """Upgrade databases created by earlier versions."""
    cols = lambda t: {r["name"] for r in db.execute(f"PRAGMA table_info({t})")}
    if "ipv" not in cols("usage") and cols("usage"):
        db.executescript("ALTER TABLE usage RENAME TO usage_old; DROP INDEX IF EXISTS usage_bucket;")
    db.executescript("""CREATE TABLE IF NOT EXISTS usage(
      bucket INTEGER, process TEXT, proto TEXT, port INTEGER, ipv INTEGER DEFAULT 0,
      tx INTEGER DEFAULT 0, rx INTEGER DEFAULT 0,
      PRIMARY KEY(bucket, process, proto, port, ipv));   -- 1-minute buckets, service port, ipv 4/6 (0 = unknown)
      CREATE INDEX IF NOT EXISTS usage_bucket ON usage(bucket);""")
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='usage_old'").fetchone():
        db.execute("INSERT INTO usage(bucket,process,proto,port,ipv,tx,rx) "
                   "SELECT bucket,process,proto,port,0,tx,rx FROM usage_old")
        db.execute("DROP TABLE usage_old")
    if "user" not in cols("connections"):
        db.execute("ALTER TABLE connections ADD COLUMN user TEXT DEFAULT ''")
    if "last_user" not in cols("executables"):
        db.execute("ALTER TABLE executables ADD COLUMN last_user TEXT DEFAULT ''")
        db.execute("UPDATE executables SET last_user=user")
    db.commit()


migrate()
traffic = []          # [(ts, bytes_sent_per_s, bytes_recv_per_s)]
rdns_cache = {}       # ip -> hostname or ""
rdns_pending = set()
DEMO = False
cap = None                 # capture.Capture when live capture is active
owners = {}                # (proto, local_port) -> (process, last_seen)
listen_ports = set()       # (proto, local_port) of listening sockets
live_rates = {}            # (process, proto, port) -> (tx_Bps, rx_Bps) over the last interval
pending_flows = {}         # flows whose socket owner was not found yet (retried once)
UNATTRIBUTED = "(unattributed)"
USAGE_KEEP_DAYS = 30
OWNER_TTL = 120
SCAN_SECS = 4
RISKY_RE = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/|\\temp\\|\\appdata\\local\\temp|/downloads/|\\downloads\\|\(deleted\)$)", re.I)
exe_live = set()           # (pid, create_time) of processes seen on the previous scan
first_scan = True
verifier = None
enforcer = protect.Enforcer()
protect_rules_cache = []
protect_on = True
alert_state = {}           # rule id -> (last packet count, last alert time)


# ---------------------------------------------------------------- helpers
def is_private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def resolve_async(ip):
    if ip in rdns_cache or ip in rdns_pending or not ip:
        return
    rdns_pending.add(ip)

    def work():
        try:
            rdns_cache[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns_cache[ip] = ""
        rdns_pending.discard(ip)
    threading.Thread(target=work, daemon=True).start()


def add_alert(kind, subject, detail):
    db.execute("INSERT INTO alerts(ts,kind,subject,detail) VALUES(?,?,?,?)",
               (time.time(), kind, subject, detail))


# ---------------------------------------------------------------- sampling
def snapshot_real():
    rows = []
    procs = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
    now = time.time()
    lp = set()
    for c in conns:
        pid = c.pid or 0
        if pid not in procs:
            try:
                p = psutil.Process(pid)
                procs[pid] = (p.name(), p.exe() or "", p.username())
            except Exception:
                procs[pid] = ("unknown", "", "")
        name, exe, user = procs[pid]
        if c.laddr and pid:
            k = ("tcp" if c.type == socket.SOCK_STREAM else "udp", c.laddr.port)
            owners[k] = (name, now)
            if c.status == "LISTEN":
                lp.add(k)
        if not c.raddr:      # skip pure listeners; they have no remote peer
            continue
        rows.append(dict(process=name, exe=exe, pid=pid, user=user,
                         proto="tcp" if c.type == socket.SOCK_STREAM else "udp",
                         laddr=c.laddr.ip, lport=c.laddr.port,
                         raddr=c.raddr.ip, rport=c.raddr.port, status=c.status))
    listen_ports.clear(); listen_ports.update(lp)
    for k in [k for k, v in owners.items() if now - v[1] > OWNER_TTL]:
        del owners[k]
    return rows


_demo_apps = [("firefox", "/usr/bin/firefox"), ("code", "/usr/share/code/code"),
              ("curl", "/usr/bin/curl"), ("telegram", "/opt/telegram/Telegram"),
              ("unknown-miner", "/tmp/.x/kworker")]
_demo_hosts = ["142.250.74.46", "151.101.1.69", "52.84.150.12", "185.199.108.153",
               "93.184.216.34", "45.9.148.200", "10.0.0.5", "2a00:1450:4001:81b::200e", "2606:4700::6810:84e5"]
_demo_state = []


def snapshot_demo():
    global _demo_state
    if not _demo_state or random.random() < 0.25:
        app = random.choice(_demo_apps)
        _demo_state.append(dict(process=app[0], exe=app[1], pid=1000 + _demo_apps.index(app),
                                user=random.choice(["alice", "alice", "root"]),
                                proto=random.choice(["tcp", "tcp", "udp"]),
                                laddr="192.168.1.20", lport=random.randint(40000, 60000),
                                raddr=random.choice(_demo_hosts),
                                rport=random.choice([443, 443, 80, 53, 8080, 4444]),
                                status="ESTABLISHED"))
    if len(_demo_state) > 14 or random.random() < 0.15:
        _demo_state.pop(random.randrange(len(_demo_state)))
    return list(_demo_state)


def service_port(proto, lport, rport):
    """The port that identifies the service: the listening port for inbound
    traffic, otherwise the remote port (local ports are ephemeral)."""
    if proto == "icmp":
        return 0
    if (proto, lport) in listen_ports:
        return lport
    if proto == "udp" and lport < 1024 <= rport:
        return lport
    return rport


def ingest_usage(items, now, dt):
    """items: [(process, proto, port, ipv, tx_bytes, rx_bytes)] accumulated over dt seconds."""
    bucket = int(now // 60) * 60
    live_rates.clear()
    with db_lock:
        for process, proto, port, ipv, tx, rx in items:
            if not (tx or rx):
                continue
            db.execute("""INSERT INTO usage(bucket,process,proto,port,ipv,tx,rx) VALUES(?,?,?,?,?,?,?)
                          ON CONFLICT(bucket,process,proto,port,ipv) DO UPDATE SET tx=tx+excluded.tx, rx=rx+excluded.rx""",
                       (bucket, process, proto, port, ipv, int(tx), int(rx)))
            k = (process, "quic" if proto == "udp" and port == 443 else proto, port)
            t0, r0 = live_rates.get(k, (0, 0))
            live_rates[k] = (t0 + tx / dt, r0 + rx / dt)
        db.commit()


def drain_capture(now, dt):
    """Resolve captured flows to processes and store them."""
    flows = cap.drain()
    flows.update({k: [a + b for a, b in zip(flows.get(k, [0, 0]), v)] for k, v in pending_flows.items()})
    retry, agg = {}, {}
    for (proto, lport, raddr, rport), (tx, rx) in flows.items():
        owner = owners.get((proto, lport))
        if owner is None and proto != "icmp":
            if (proto, lport, raddr, rport) not in pending_flows:    # one retry on the next sample
                retry[(proto, lport, raddr, rport)] = [tx, rx]
                continue
        name = owner[0] if owner else UNATTRIBUTED
        k = (name, proto, service_port(proto, lport, rport), 6 if ":" in raddr else 4)
        a = agg.setdefault(k, [0, 0]); a[0] += tx; a[1] += rx
    pending_flows.clear(); pending_flows.update(retry)
    ingest_usage([(n, p, port, v, t, r) for (n, p, port, v), (t, r) in agg.items()], now, dt)


def demo_usage(rows, now, dt):
    items = []
    for r in rows:
        heavy = r["process"] in ("firefox", "unknown-miner")
        rx = random.randint(2_000, 400_000 if heavy else 40_000) * dt
        tx = random.randint(500, 60_000 if heavy else 8_000) * dt
        items.append((r["process"], r["proto"], r["rport"], 6 if ":" in r["raddr"] else 4, tx, rx))
    ingest_usage(items, now, dt)



# ---------------------------------------------------------------- log analysis (executables)
def _split_name(path):
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1]


def on_verified(path, info):
    with db_lock:
        row = db.execute("SELECT baseline FROM executables WHERE path=?", (path,)).fetchone()
        db.execute("""UPDATE executables SET publisher=?, signed=?, verified_by=?, sha256=?, status='done'
                      WHERE path=?""", (info["publisher"], info["signed"], info["verified_by"], info["sha256"], path))
        if row and not row["baseline"]:
            if not info["signed"]:
                add_alert("unsigned-exe", _split_name(path), f"first run of unsigned/unverified file {path} ({info['verified_by']})")
            elif "MODIFIED" in info["verified_by"]:
                add_alert("exe-modified", _split_name(path), path)
        db.commit()


def scan_processes(now):
    """Record the first time each executable path is seen running."""
    global first_scan, exe_live
    live, new = set(), []
    for p in psutil.process_iter(["pid", "exe", "create_time", "username"]):
        exe = p.info.get("exe")
        if not exe:
            continue
        key = (p.info["pid"], p.info["create_time"])
        live.add(key)
        if key not in exe_live:
            new.append((exe, p.info["create_time"], p.info.get("username") or "", p.info["pid"]))
    exe_live = live
    if not new:
        return
    with db_lock:
        for exe, started, user, pid in new:
            try:
                st = os.stat(exe[:-10] if exe.endswith(" (deleted)") else exe)
                mtime = st.st_mtime
            except OSError:
                mtime = None
            row = db.execute("SELECT mtime FROM executables WHERE path=?", (exe,)).fetchone()
            db.execute("INSERT INTO exe_runs(path,ts,user,pid) VALUES(?,?,?,?)", (exe, started, user, pid))
            if row is None:
                db.execute("""INSERT INTO executables(path,filename,first_run,last_run,user,last_user,baseline,risky,mtime)
                              VALUES(?,?,?,?,?,?,?,?,?)""",
                           (exe, _split_name(exe), started, started, user, user, int(first_scan),
                            int(bool(RISKY_RE.search(exe))), mtime))
                if not first_scan:
                    add_alert("new-exe", _split_name(exe), f"first run from {exe}")
                verifier.submit(exe)
            else:
                changed = mtime is not None and row["mtime"] is not None and abs(mtime - row["mtime"]) > 1
                db.execute("UPDATE executables SET user=CASE WHEN ?<first_run THEN ? ELSE user END, "
                           "last_user=CASE WHEN ?>=last_run THEN ? ELSE last_user END, "
                           "last_run=MAX(last_run,?), first_run=MIN(first_run,?), runs=runs+1, "
                           "mtime=COALESCE(?,mtime), modified=modified OR ? WHERE path=?",
                           (started, user, started, user, started, started, mtime, int(changed), exe))
                if changed:
                    db.execute("UPDATE executables SET status='pending' WHERE path=?", (exe,))
                    add_alert("exe-modified", _split_name(exe), f"file changed on disk since first run: {exe}")
                    verifier.submit(exe)
        db.commit()
    first_scan = False


def q_executables(params):
    p = lambda k: (params.get(k) or [""])[0]
    where, args = [], []
    if p("signed") == "yes":
        where.append("signed=1")
    elif p("signed") == "no":
        where.append("signed=0 AND status='done'")
    elif p("signed") == "pending":
        where.append("status='pending'")
    if p("since").isdigit():
        where.append("first_run >= ?"); args.append(time.time() - int(p("since")))
    if p("risky") == "1":
        where.append("risky=1")
    if p("baseline") == "0":
        where.append("baseline=0")
    if p("q"):
        where.append("(filename LIKE ? OR path LIKE ? OR publisher LIKE ? OR sha256 LIKE ? OR user LIKE ? OR last_user LIKE ?)")
        args += [f"%{p('q')}%"] * 6
    sort = p("sort") if p("sort") in ("filename", "path", "first_run", "last_run", "runs", "publisher", "signed", "user", "last_user") else "first_run"
    order = "ASC" if p("dir") == "asc" else "DESC"
    with db_lock:
        return [dict(r) for r in db.execute(
            f"SELECT * FROM executables {'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY {sort} {order} LIMIT 2000", args)]


def q_exe_runs(params):
    path = (params.get("path") or [""])[0]
    with db_lock:
        return [dict(r) for r in db.execute(
            "SELECT ts, user, pid FROM exe_runs WHERE path=? ORDER BY ts DESC LIMIT 200", (path,))]


def executables_csv(params):
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["filename", "path", "first_run", "publisher", "signed", "verified_by", "sha256", "runs", "last_run", "first_run_by", "last_run_by"])
    for r in q_executables(params):
        w.writerow([r["filename"], r["path"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["first_run"])),
                    r["publisher"], {1: "yes", 0: "no"}.get(r["signed"], "pending"), r["verified_by"],
                    r["sha256"], r["runs"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_run"])),
                    r["user"], r["last_user"]])
    return buf.getvalue()


# ---------------------------------------------------------------- net protect
def load_rules():
    global protect_rules_cache, protect_on
    with db_lock:
        protect_rules_cache = [dict(r) for r in db.execute("SELECT * FROM rules ORDER BY id")]
        m = db.execute("SELECT v FROM settings WHERE k='protect_on'").fetchone()
        protect_on = (m["v"] != "0") if m else True


def reapply():
    """Reload rules from the DB and push them to the firewall. -> error or None."""
    load_rules()
    with db_lock:
        exes = [r["path"] for r in db.execute("SELECT path FROM executables")]
    err = enforcer.apply(protect_rules_cache, protect_on, exes)
    enforcer.error = err or (None if enforcer.backend else enforcer.error)
    if not err:
        enforcer.refresh_paths(protect_rules_cache if protect_on else [])
    return err


def protect_loop():
    """Keeps path-rule port sets fresh and raises alerts when a rule starts dropping traffic."""
    last_poll = 0
    while True:
        time.sleep(protect.REFRESH)
        if not (protect_on and enforcer.backend and protect_rules_cache):
            continue
        try:
            enforcer.refresh_paths(protect_rules_cache)
            now = time.time()
            if now - last_poll > 10:
                last_poll = now
                for rid, (pk, _) in enforcer.counters().items():
                    prev, t = alert_state.get(rid, (0, 0))
                    if pk > prev and now - t > 300:
                        r = next((x for x in protect_rules_cache if x["id"] == rid), None)
                        if r:
                            with db_lock:
                                add_alert("blocked", f"rule #{rid}", f"{protect.describe(r)}: {pk - prev} packets dropped")
                                db.commit()
                        alert_state[rid] = (pk, now)
                    else:
                        alert_state[rid] = (pk, t) if pk > prev else (prev, t)
        except Exception as e:                      # never let enforcement thread die
            enforcer.error = str(e)[:200]


def q_protect():
    load_rules()
    counts = enforcer.counters()
    rules = []
    for r in protect_rules_cache:
        pk, by = counts.get(r["id"], (0, 0))
        rules.append({**r, "summary": protect.describe(r), "packets": pk, "bytes": by,
                      "matched_ports": enforcer.matched.get(r["id"]) if r["kind"] == "path" else None})
    return {"backend": enforcer.backend, "error": enforcer.error, "enabled": protect_on, "rules": rules,
            "platform": sys.platform}


def protect_add(b):
    rule, err, warn = protect.validate(b)
    if err:
        return {"error": err}, 400
    if warn and not b.get("confirm"):
        return {"confirm": warn}, 409
    with db_lock:
        db.execute("INSERT INTO rules(kind,proto,port,direction,path,enabled,note,created) VALUES(?,?,?,?,?,1,?,?)",
                   (rule["kind"], rule["proto"], rule["port"], rule["direction"], rule["path"], rule["note"], time.time()))
        db.commit()
    err = reapply()
    return ({"ok": True, "warning": err} if err else {"ok": True}), 200


def protect_change(sql, args):
    with db_lock:
        db.execute(sql, args)
        db.commit()
    err = reapply()
    return {"ok": True, "warning": err} if err else {"ok": True}


def sample_loop():
    last = None
    seen_apps = {r["target"] for r in db.execute("SELECT DISTINCT process AS target FROM connections")}
    seen_hosts = {r["target"] for r in db.execute("SELECT DISTINCT raddr AS target FROM connections")}
    prev_io = None
    last_t = time.time() - SAMPLE_SECS
    last_prune = 0
    last_scan = 0
    while True:
        now = time.time()
        dt = max(now - last_t, 0.001); last_t = now
        rows = snapshot_demo() if DEMO else snapshot_real()
        if DEMO:
            demo_usage(rows, now, dt)
        elif cap and cap.running:
            drain_capture(now, dt)
        if now - last_scan >= SCAN_SECS:
            last_scan = now
            try:
                scan_processes(now)
            except Exception as e:
                print("process scan failed:", e)
        if now - last_prune > 3600:
            last_prune = now
            with db_lock:
                db.execute("DELETE FROM usage WHERE bucket < ?", (now - USAGE_KEEP_DAYS * 86400,))
                db.execute("DELETE FROM exe_runs WHERE ts < ?", (now - 90 * 86400,))
                db.commit()
        with db_lock:
            keys = set()
            for r in rows:
                key = f"{r['pid']}|{r['proto']}|{r['laddr']}:{r['lport']}|{r['raddr']}:{r['rport']}"
                keys.add(key)
                if not is_private(r["raddr"]):
                    resolve_async(r["raddr"])
                cur = db.execute("SELECT 1 FROM connections WHERE key=?", (key,)).fetchone()
                if cur:
                    db.execute("UPDATE connections SET last_seen=?, hits=hits+1, active=1, status=? WHERE key=?",
                               (now, r["status"], key))
                else:
                    db.execute("""INSERT INTO connections(key,process,exe,pid,proto,laddr,lport,raddr,rport,
                                  status,first_seen,last_seen,user) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (key, r["process"], r["exe"], r["pid"], r["proto"], r["laddr"],
                                r["lport"], r["raddr"], r["rport"], r["status"], now, now, r.get("user", "")))
                    if r["process"] not in seen_apps:
                        seen_apps.add(r["process"])
                        add_alert("new-app", r["process"], f"first network activity ({r['exe'] or 'path unknown'})")
                    if r["raddr"] not in seen_hosts and not is_private(r["raddr"]):
                        seen_hosts.add(r["raddr"])
                        add_alert("new-host", r["raddr"], f"{r['process']} -> {r['raddr']}:{r['rport']}")
                    pol = db.execute("SELECT policy FROM labels WHERE policy='block' AND ((kind='app' AND target=?) "
                                     "OR (kind='host' AND target=?))", (r["process"], r["raddr"])).fetchone()
                    if pol:
                        add_alert("blocked-attempt", r["process"], f"connection to flagged target {r['raddr']}:{r['rport']}")
            if keys:
                qs = ",".join("?" * len(keys))
                db.execute(f"UPDATE connections SET active=0 WHERE active=1 AND key NOT IN ({qs})", tuple(keys))
            else:
                db.execute("UPDATE connections SET active=0 WHERE active=1")
            db.commit()
        # throughput
        io = psutil.net_io_counters()
        if DEMO:
            tx, rx = random.randint(1_000, 80_000), random.randint(5_000, 900_000)
        elif prev_io:
            dt = max(now - prev_io[0], 0.001)
            tx, rx = (io.bytes_sent - prev_io[1]) / dt, (io.bytes_recv - prev_io[2]) / dt
        else:
            tx = rx = 0
        prev_io = (now, io.bytes_sent, io.bytes_recv)
        traffic.append((now, int(tx), int(rx)))
        while traffic and traffic[0][0] < now - TRAFFIC_KEEP:
            traffic.pop(0)
        time.sleep(SAMPLE_SECS)


# ---------------------------------------------------------------- queries
def q_connections(params):
    where, args = [], []
    p = lambda k: (params.get(k) or [""])[0]
    if p("active") == "1":
        where.append("c.active=1")
    if p("proto") == "quic":                     # QUIC / HTTP3 = UDP to port 443
        where.append("c.proto='udp' AND c.rport=443")
    elif p("proto") == "udp":
        where.append("c.proto='udp' AND c.rport!=443")
    elif p("proto"):
        where.append("c.proto=?"); args.append(p("proto"))
    if p("ipv") in ("4", "6"):
        where.append("c.raddr %s LIKE '%%:%%'" % ("" if p("ipv") == "6" else "NOT"))
    if p("process"):
        where.append("c.process=?"); args.append(p("process"))
    if p("user"):
        where.append("c.user=?"); args.append(p("user"))
    if p("remote") == "public":
        where.append("c.raddr NOT LIKE '10.%' AND c.raddr NOT LIKE '192.168.%' AND c.raddr NOT LIKE '127.%' "
                     "AND c.raddr NOT LIKE '172.16.%' AND c.raddr NOT LIKE '172.2_.%' AND c.raddr NOT LIKE '172.30.%' "
                     "AND c.raddr NOT LIKE '172.31.%' AND c.raddr NOT LIKE '169.254.%' AND c.raddr!='::1' "
                     "AND c.raddr NOT LIKE 'fe80:%' AND c.raddr NOT LIKE 'fc%:%' AND c.raddr NOT LIKE 'fd%:%'")
    if p("label") == "labelled":
        where.append("(a.label!='' OR h.label!='')")
    elif p("label") == "unlabelled":
        where.append("(COALESCE(a.label,'')='' AND COALESCE(h.label,'')='')")
    elif p("label"):
        where.append("(a.label=? OR h.label=?)"); args += [p("label"), p("label")]
    if p("policy"):
        where.append("(a.policy=? OR h.policy=?)"); args += [p("policy"), p("policy")]
    if p("q"):
        like = f"%{p('q')}%"
        where.append("(c.process LIKE ? OR c.raddr LIKE ? OR CAST(c.rport AS TEXT) LIKE ? OR c.exe LIKE ? "
                     "OR a.label LIKE ? OR h.label LIKE ? OR a.note LIKE ? OR h.note LIKE ? OR c.user LIKE ?)")
        args += [like] * 9
    sort = p("sort") if p("sort") in ("process", "pid", "proto", "raddr", "rport", "status",
                                      "first_seen", "last_seen", "hits", "user") else "last_seen"
    order = "ASC" if p("dir") == "asc" else "DESC"
    sql = f"""SELECT c.*, COALESCE(a.label,'') AS app_label, COALESCE(a.color,'') AS app_color,
                     COALESCE(a.policy,'none') AS app_policy,
                     COALESCE(h.label,'') AS host_label, COALESCE(h.color,'') AS host_color,
                     COALESCE(h.policy,'none') AS host_policy
              FROM connections c
              LEFT JOIN labels a ON a.kind='app' AND a.target=c.process
              LEFT JOIN labels h ON h.kind='host' AND h.target=c.raddr
              {'WHERE ' + ' AND '.join(where) if where else ''}
              ORDER BY {sort} {order} LIMIT 1000"""
    with db_lock:
        out = [dict(r) for r in db.execute(sql, args)]
    for r in out:
        r["hostname"] = rdns_cache.get(r["raddr"], "")
        r["ipv"] = 6 if ":" in r["raddr"] else 4
        r["proto_label"] = "quic" if r["proto"] == "udp" and r["rport"] == 443 else r["proto"]
    return out


def q_apps():
    sql = """SELECT c.process, MIN(c.exe) AS exe, COUNT(*) AS conns, SUM(c.active) AS active,
                    COUNT(DISTINCT c.raddr) AS hosts, MIN(c.first_seen) AS first_seen,
                    MAX(c.last_seen) AS last_seen,
                    COALESCE(a.label,'') AS label, COALESCE(a.color,'') AS color,
                    COALESCE(a.policy,'none') AS policy, COALESCE(a.note,'') AS note
             FROM connections c LEFT JOIN labels a ON a.kind='app' AND a.target=c.process
             GROUP BY c.process ORDER BY active DESC, last_seen DESC"""
    with db_lock:
        return [dict(r) for r in db.execute(sql)]


def q_labels():
    with db_lock:
        return [dict(r) for r in db.execute("SELECT * FROM labels ORDER BY label")]


def svc_name(proto, port):
    if not port:
        return ""
    try:
        return socket.getservbyport(port, proto if proto in ("tcp", "udp") else "tcp")
    except OSError:
        return ""


USAGE_SRC = """(SELECT bucket, process, port, ipv, tx, rx,
                       CASE WHEN proto='udp' AND port=443 THEN 'quic' ELSE proto END AS proto FROM usage) u"""


def usage_filters(p, rng):
    """Shared by the usage table and chart. proto: tcp | udp (non-QUIC) | quic | icmp."""
    where, args = ["bucket >= ?"], [time.time() - rng]
    if p("proto"):
        where.append("proto=?"); args.append(p("proto"))
    if p("ipv") in ("4", "6"):
        where.append("ipv=?"); args.append(int(p("ipv")))
    if p("process"):
        where.append("process=?"); args.append(p("process"))
    if p("q"):
        where.append("(process LIKE ? OR CAST(port AS TEXT) LIKE ? OR proto LIKE ?)"); args += [f"%{p('q')}%"] * 3
    return where, args


def _range(p):
    try:
        return max(60, min(int(p("range", "3600")), USAGE_KEEP_DAYS * 86400))
    except ValueError:
        return 3600


def q_usage(params):
    p = lambda k, d="": (params.get(k) or [d])[0]
    rng = _range(p)
    group = {"app": ["process"], "app_port": ["process", "proto", "port"],
             "port": ["proto", "port"], "proto": ["proto"]}.get(p("group", "app_port"), ["process", "proto", "port"])
    where, args = usage_filters(p, rng)
    sort = p("sort", "total") if p("sort", "total") in ("process", "proto", "port", "tx", "rx", "total") else "total"
    if sort in ("process", "proto", "port") and sort not in group:
        sort = "total"
    order = "ASC" if p("dir") == "asc" else "DESC"
    sql = f"""SELECT {', '.join(group)}, SUM(tx) AS tx, SUM(rx) AS rx, SUM(tx)+SUM(rx) AS total
              FROM {USAGE_SRC} WHERE {' AND '.join(where)} GROUP BY {', '.join(group)}
              ORDER BY {sort} {order} LIMIT 500"""
    with db_lock:
        rows = [dict(r) for r in db.execute(sql, args)]
    for r in rows:
        if "port" in r:
            r["service"] = "https (HTTP/3)" if r["proto"] == "quic" else svc_name(r["proto"], r["port"])
    return rows


def q_usage_series(params):
    p = lambda k, d="": (params.get(k) or [d])[0]
    rng = _range(p)
    try:
        top = max(1, min(int(p("top", "6")), 12))
    except ValueError:
        top = 6
    where, args = usage_filters(p, rng)
    step = 60 if rng <= 7200 else 600 if rng <= 86400 * 2 else 3600
    with db_lock:
        tops = [r["process"] for r in db.execute(
            f"SELECT process FROM {USAGE_SRC} WHERE {' AND '.join(where)} GROUP BY process ORDER BY SUM(tx+rx) DESC LIMIT ?", args + [top])]
        rows = db.execute(f"SELECT (bucket/?)*? AS b, process, SUM(tx+rx) AS n FROM {USAGE_SRC} WHERE {' AND '.join(where)} GROUP BY b, process",
                          [step, step] + args).fetchall()
    series = {}
    for r in rows:
        name = r["process"] if r["process"] in tops else "other"
        series.setdefault(r["b"], {}); series[r["b"]][name] = series[r["b"]].get(name, 0) + r["n"]
    return {"step": step, "apps": tops + (["other"] if any("other" in v for v in series.values()) else []),
            "points": [{"t": t, "v": v} for t, v in sorted(series.items())]}


def q_usage_live():
    out = {}
    for (proc, proto, port), (tx, rx) in list(live_rates.items()):
        a = out.setdefault(proc, {"process": proc, "tx": 0, "rx": 0, "ports": {}})
        a["tx"] += tx; a["rx"] += rx
        a["ports"][f"{proto}/{port}" if proto != "icmp" else "icmp"] = a["ports"].get(f"{proto}/{port}" if proto != "icmp" else "icmp", 0) + tx + rx
    res = sorted(out.values(), key=lambda a: -(a["tx"] + a["rx"]))
    for a in res:
        a["ports"] = [k for k, _ in sorted(a["ports"].items(), key=lambda kv: -kv[1])[:4]]
    return res


def capture_status():
    if DEMO:
        return {"mode": "demo", "error": None}
    if cap is None:
        return {"mode": "off", "error": "capture disabled (--no-capture)"}
    return {"mode": "sniffer" if cap.running else "unavailable", "error": cap.error,
            "packets": cap.packets, "bytes": cap.bytes}


def q_alerts(params):
    with db_lock:
        return [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 300")]


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)
        if u.path == "/api/connections": return self.send_json(q_connections(params))
        if u.path == "/api/apps": return self.send_json(q_apps())
        if u.path == "/api/labels": return self.send_json(q_labels())
        if u.path == "/api/alerts": return self.send_json(q_alerts(params))
        if u.path == "/api/executables": return self.send_json(q_executables(params))
        if u.path == "/api/executables/runs": return self.send_json(q_exe_runs(params))
        if u.path == "/api/executables.csv":
            data = executables_csv(params).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=netwatch-executables.csv")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/api/protect": return self.send_json(q_protect())
        if u.path == "/api/usage": return self.send_json(q_usage(params))
        if u.path == "/api/usage/series": return self.send_json(q_usage_series(params))
        if u.path == "/api/usage/live": return self.send_json(q_usage_live())
        if u.path == "/api/capture": return self.send_json(capture_status())
        if u.path == "/api/traffic":
            since = float((params.get("since") or [0])[0])
            return self.send_json([t for t in traffic if t[0] > since])
        if u.path == "/api/export":
            return self.send_json(q_connections(params))
        path = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
        full = os.path.normpath(os.path.join(HERE, "static", path))
        if not full.startswith(os.path.join(HERE, "static")) or not os.path.isfile(full):
            return self.send_json({"error": "not found"}, 404)
        ctype = {"html": "text/html", "js": "text/javascript", "css": "text/css"}.get(full.rsplit(".", 1)[-1], "application/octet-stream")
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        u = urlparse(self.path)
        try:
            b = self.body()
        except Exception:
            return self.send_json({"error": "bad json"}, 400)
        if u.path == "/api/labels":
            if b.get("kind") not in ("app", "host") or not b.get("target"):
                return self.send_json({"error": "kind(app|host) and target required"}, 400)
            if b.get("policy", "none") not in ("none", "trusted", "block", "watch"):
                return self.send_json({"error": "bad policy"}, 400)
            with db_lock:
                db.execute("""INSERT INTO labels(kind,target,label,color,policy,note) VALUES(?,?,?,?,?,?)
                              ON CONFLICT(kind,target) DO UPDATE SET label=excluded.label, color=excluded.color,
                              policy=excluded.policy, note=excluded.note""",
                           (b["kind"], b["target"], b.get("label", ""), b.get("color", ""),
                            b.get("policy", "none"), b.get("note", "")))
                db.commit()
            return self.send_json({"ok": True})
        if u.path == "/api/protect/rules":
            res, code = protect_add(b)
            return self.send_json(res, code)
        if u.path == "/api/protect/toggle":
            return self.send_json(protect_change("UPDATE rules SET enabled=? WHERE id=?", (int(bool(b.get("enabled"))), int(b.get("id", 0)))))
        if u.path == "/api/protect/master":
            return self.send_json(protect_change("INSERT INTO settings(k,v) VALUES('protect_on',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                                                 ("1" if b.get("enabled") else "0",)))
        if u.path == "/api/alerts/ack":
            with db_lock:
                db.execute("UPDATE alerts SET ack=1 WHERE ?=0 OR id=?", (b.get("id", 0), b.get("id", 0)))
                db.commit()
            return self.send_json({"ok": True})
        self.send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        u = urlparse(self.path)
        if u.path == "/api/labels":
            q = parse_qs(u.query)
            with db_lock:
                db.execute("DELETE FROM labels WHERE kind=? AND target=?",
                           ((q.get("kind") or [""])[0], (q.get("target") or [""])[0]))
                db.commit()
            return self.send_json({"ok": True})
        if u.path == "/api/protect/rules":
            rid = (parse_qs(u.query).get("id") or ["0"])[0]
            return self.send_json(protect_change("DELETE FROM rules WHERE id=?", (int(rid) if rid.isdigit() else 0,)))
        self.send_json({"error": "not found"}, 404)


def main():
    global DEMO, cap
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--demo", action="store_true", help="generate synthetic traffic")
    ap.add_argument("--no-capture", action="store_true", help="skip packet capture (no per-app bandwidth)")
    ap.add_argument("--loopback", action="store_true", help="also count host-local (127.0.0.1) traffic")
    a = ap.parse_args()
    DEMO = a.demo
    if not DEMO and not a.no_capture:
        cap = capture.Capture(loopback=a.loopback)
        if not cap.start():
            print(f"per-app bandwidth disabled: {cap.error}")
    global verifier
    verifier = inventory.Verifier(on_verified)
    err = reapply()
    if enforcer.backend:
        print(f"Net Protect: {enforcer.backend}, {len(protect_rules_cache)} rule(s) loaded" + (f" (warning: {err})" if err else ""))
        atexit.register(enforcer.cleanup)                       # fail-open: rules vanish with the monitor
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    else:
        print(f"Net Protect disabled: {enforcer.error}")
    threading.Thread(target=protect_loop, daemon=True).start()
    threading.Thread(target=sample_loop, daemon=True).start()
    print(f"NetWatch on http://{a.host}:{a.port}  ({'demo data' if DEMO else 'live data'})")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
