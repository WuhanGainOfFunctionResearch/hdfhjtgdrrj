#!/usr/bin/env python3
"""NetWatch - a small GlassWire-style network monitor.

Backend: samples per-process connections + interface throughput with psutil,
stores history/labels in SQLite, serves a JSON API and the static HTML UI.
Only the standard library and psutil are needed.

    pip install -r requirements.txt
    python server.py            # http://127.0.0.1:8765
    python server.py --demo     # synthetic data, no privileges needed
"""
import argparse, json, os, random, socket, sqlite3, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import psutil

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
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, subject TEXT,
  detail TEXT, ack INTEGER DEFAULT 0);
""")

traffic = []          # [(ts, bytes_sent_per_s, bytes_recv_per_s)]
rdns_cache = {}       # ip -> hostname or ""
rdns_pending = set()
DEMO = False


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
    for c in conns:
        if not c.raddr:      # skip pure listeners; they have no remote peer
            continue
        pid = c.pid or 0
        if pid not in procs:
            try:
                p = psutil.Process(pid)
                procs[pid] = (p.name(), p.exe() or "")
            except Exception:
                procs[pid] = ("unknown", "")
        name, exe = procs[pid]
        rows.append(dict(process=name, exe=exe, pid=pid,
                         proto="tcp" if c.type == socket.SOCK_STREAM else "udp",
                         laddr=c.laddr.ip, lport=c.laddr.port,
                         raddr=c.raddr.ip, rport=c.raddr.port, status=c.status))
    return rows


_demo_apps = [("firefox", "/usr/bin/firefox"), ("code", "/usr/share/code/code"),
              ("curl", "/usr/bin/curl"), ("telegram", "/opt/telegram/Telegram"),
              ("unknown-miner", "/tmp/.x/kworker")]
_demo_hosts = ["142.250.74.46", "151.101.1.69", "52.84.150.12", "185.199.108.153",
               "93.184.216.34", "45.9.148.200", "10.0.0.5"]
_demo_state = []


def snapshot_demo():
    global _demo_state
    if not _demo_state or random.random() < 0.25:
        app = random.choice(_demo_apps)
        _demo_state.append(dict(process=app[0], exe=app[1], pid=1000 + _demo_apps.index(app),
                                proto=random.choice(["tcp", "tcp", "udp"]),
                                laddr="192.168.1.20", lport=random.randint(40000, 60000),
                                raddr=random.choice(_demo_hosts),
                                rport=random.choice([443, 443, 80, 53, 8080, 4444]),
                                status="ESTABLISHED"))
    if len(_demo_state) > 14 or random.random() < 0.15:
        _demo_state.pop(random.randrange(len(_demo_state)))
    return list(_demo_state)


def sample_loop():
    last = None
    seen_apps = {r["target"] for r in db.execute("SELECT DISTINCT process AS target FROM connections")}
    seen_hosts = {r["target"] for r in db.execute("SELECT DISTINCT raddr AS target FROM connections")}
    prev_io = None
    while True:
        now = time.time()
        rows = snapshot_demo() if DEMO else snapshot_real()
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
                                  status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (key, r["process"], r["exe"], r["pid"], r["proto"], r["laddr"],
                                r["lport"], r["raddr"], r["rport"], r["status"], now, now))
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
    if p("proto"):
        where.append("c.proto=?"); args.append(p("proto"))
    if p("process"):
        where.append("c.process=?"); args.append(p("process"))
    if p("remote") == "public":
        where.append("c.raddr NOT LIKE '10.%' AND c.raddr NOT LIKE '192.168.%' AND c.raddr NOT LIKE '127.%' "
                     "AND c.raddr NOT LIKE '172.16.%' AND c.raddr!='::1'")
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
                     "OR a.label LIKE ? OR h.label LIKE ? OR a.note LIKE ? OR h.note LIKE ?)")
        args += [like] * 8
    sort = p("sort") if p("sort") in ("process", "pid", "proto", "raddr", "rport", "status",
                                      "first_seen", "last_seen", "hits") else "last_seen"
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
        self.send_json({"error": "not found"}, 404)


def main():
    global DEMO
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--demo", action="store_true", help="generate synthetic traffic")
    a = ap.parse_args()
    DEMO = a.demo
    threading.Thread(target=sample_loop, daemon=True).start()
    print(f"NetWatch on http://{a.host}:{a.port}  ({'demo data' if DEMO else 'live data'})")
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
