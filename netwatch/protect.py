"""Net Protect: turn rules (protocol / port / program path) into real firewall rules.

Linux   : nftables, one table `inet netwatch` (needs root). Port and protocol rules are
          static nft rules. nftables cannot match a program, so a path rule keeps a set of
          the local ports currently owned by matching processes and drops traffic on
          those ports; the set is refreshed every REFRESH seconds. A brand-new connection
          can therefore leak its first packet(s) before its port is discovered.
Windows : Windows Defender Firewall via PowerShell New-NetFirewallRule (needs Administrator).
          *Not tested* in the development environment.
Other   : rules are stored but not enforced.

Everything is removed on exit (fail-open) so a stopped monitor can never lock you out.
"""
import fnmatch, json, os, re, shutil, socket, subprocess, threading, time

import psutil

TABLE = "netwatch"
REFRESH = 0.5
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(\s*,\s*\d{1,5}(-\d{1,5})?)*$")
WIN = os.name == "nt"


# ------------------------------------------------------------------ validation
def validate(d):
    """-> (clean_rule, error, confirm_message)."""
    kind = d.get("kind")
    direction = d.get("direction", "both")
    if kind not in ("protocol", "port", "path"):
        return None, "kind must be protocol, port or path", None
    if direction not in ("in", "out", "both"):
        return None, "direction must be in, out or both", None
    r = {"kind": kind, "direction": direction, "proto": "any", "port": "", "path": "",
         "note": str(d.get("note", ""))[:200]}
    warn = None
    if kind == "protocol":
        r["proto"] = d.get("proto")
        if r["proto"] not in ("tcp", "udp", "icmp"):
            return None, "protocol must be tcp, udp or icmp", None
        if r["proto"] in ("tcp", "udp"):
            warn = f"This blocks ALL {r['proto'].upper()} traffic (except loopback) and will cut your internet access"
    elif kind == "port":
        r["proto"] = d.get("proto", "any")
        if r["proto"] not in ("tcp", "udp", "any"):
            return None, "protocol must be tcp, udp or any", None
        ports = str(d.get("port", "")).replace(" ", "")
        if not PORTS_RE.match(ports):
            return None, "ports look like 25 or 80,443 or 8000-8100", None
        spans = [tuple(map(int, x.split("-"))) if "-" in x else (int(x),) * 2 for x in ports.split(",")]
        if any(not (1 <= a <= b <= 65535) for a, b in spans):
            return None, "ports must be 1-65535 (and ranges ascending)", None
        r["port"] = ports
        common = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS"}
        hit = [f"{n} ({p})" for p, n in common.items() if any(a <= p <= b for a, b in spans)]
        if hit:
            warn = "This includes common port(s) " + ", ".join(hit) + " and may break normal browsing or remote access"
    else:
        path = str(d.get("path", "")).strip()
        if not (path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path) or path.startswith("\\\\")):
            return None, "path must be absolute (/usr/bin/x, /tmp/ for a folder, C:\\Tools\\x.exe)", None
        if not path.endswith(("/", "\\")) and not re.search(r"[*?]", path) and not WIN:
            path = os.path.realpath(path)            # psutil reports resolved paths
        r["path"] = path
    return r, None, warn


def match_path(pat, exe):
    """Exact file, folder prefix (ends with / or \\) or wildcard (* ?)."""
    if not exe:
        return False
    exe = exe[:-10] if exe.endswith(" (deleted)") else exe
    if WIN:
        pat, exe = pat.lower(), exe.lower()
    if pat.endswith(("/", "\\")):
        return exe.startswith(pat)
    if re.search(r"[*?]", pat):
        return fnmatch.fnmatchcase(exe, pat)
    return exe == pat


def describe(r):
    d = {"in": "inbound", "out": "outbound", "both": "in+out"}[r["direction"]]
    if r["kind"] == "protocol":
        return f"all {r['proto'].upper()}{' (ping)' if r['proto'] == 'icmp' else ''} {d}"
    if r["kind"] == "port":
        return f"{'tcp+udp' if r['proto'] == 'any' else r['proto']} port {r['port']} {d}"
    return f"program {r['path']} {d}"


# ------------------------------------------------------------------ nft rendering
def render_nft(rules):
    out, inn, sets = [], [], []
    for r in rules:
        if not r["enabled"]:
            continue
        tag = f'comment "nw-{r["id"]}"'
        dirs = ["out", "in"] if r["direction"] == "both" else [r["direction"]]
        for d in dirs:
            chain = out if d == "out" else inn
            iface = "oifname" if d == "out" else "iifname"
            if r["kind"] == "protocol":
                if r["proto"] == "icmp":
                    chain.append(f"icmp type {{ echo-request, echo-reply }} counter drop {tag}")
                    chain.append(f"icmpv6 type {{ echo-request, echo-reply }} counter drop {tag}")
                else:
                    chain.append(f'{iface} != "lo" meta l4proto {r["proto"]} counter drop {tag}')
            elif r["kind"] == "port":
                protos = "{ tcp, udp }" if r["proto"] == "any" else r["proto"]
                chain.append(f"meta l4proto {protos} th dport {{ {r['port']} }} counter drop {tag}")
            else:
                field = "sport" if d == "out" else "dport"       # our own local port
                chain.append(f"meta l4proto . th {field} @p{r['id']} counter drop {tag}")
        if r["kind"] == "path":
            sets.append(f"  set p{r['id']} {{ type inet_proto . inet_service; }}")
    if not (out or inn):
        return ""
    body = "\n".join(sets)
    ch = lambda name, hook, rs: (f"  chain {name} {{ type filter hook {hook} priority 0; policy accept;\n"
                                 + "".join(f"    {x}\n" for x in rs) + "  }")
    return f"table inet {TABLE} {{\n{body}\n{ch('output', 'output', out)}\n{ch('input', 'input', inn)}\n}}\n"


class Enforcer:
    def __init__(self):
        self.lock = threading.Lock()
        self.error = None
        self.backend = None
        self.pushed = {}        # rule id -> frozenset of ports last pushed to its nft set
        self.matched = {}       # rule id -> number of local ports currently matched
        self._exe_cache = {}
        if WIN:
            if shutil.which("powershell"):
                self.backend = "windows-firewall"
            else:
                self.error = "powershell not found"
        elif shutil.which("nft"):
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                self.error = "needs root to change firewall rules (run with sudo)"
            else:
                self.backend = "nftables"
        else:
            self.error = "nft (nftables) is not installed; rules are saved but not enforced"

    # ---------------------------------------------------------------- apply
    def apply(self, rules, on, known_exes=()):
        """Replace everything NetWatch has installed with the given rules. -> error or None."""
        if not self.backend:
            return self.error
        with self.lock:
            self.pushed = {}
            self.matched = {}
            active = [r for r in rules if r["enabled"]] if on else []
            if self.backend == "nftables":
                text = render_nft(active)
                script = f"table inet {TABLE}\ndelete table inet {TABLE}\n{text}"
                r = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True)
                return r.stderr.strip() or None if r.returncode else None
            return self._apply_windows(active, known_exes)

    def cleanup(self):
        if self.backend:
            self.apply([], False)

    def _apply_windows(self, rules, exes):
        q = lambda s: "'" + s.replace("'", "''") + "'"
        ps = ['$ErrorActionPreference="Stop"',
              "Get-NetFirewallRule -Group NetWatch -ErrorAction SilentlyContinue | Remove-NetFirewallRule"]
        for r in rules:
            for d in (["Outbound", "Inbound"] if r["direction"] == "both" else
                      ["Outbound" if r["direction"] == "out" else "Inbound"]):
                base = f"New-NetFirewallRule -DisplayName {q('NetWatch #%d' % r['id'])} -Group NetWatch -Direction {d} -Action Block"
                portarg = "-RemotePort" if d == "Outbound" else "-LocalPort"
                if r["kind"] == "protocol":
                    if r["proto"] == "icmp":
                        ps += [f"{base} -Protocol ICMPv4 -IcmpType 8,0", f"{base} -Protocol ICMPv6 -IcmpType 128,129"]
                    else:
                        ps.append(f"{base} -Protocol {r['proto'].upper()}")
                elif r["kind"] == "port":
                    for pr in (["TCP", "UDP"] if r["proto"] == "any" else [r["proto"].upper()]):
                        ps.append(f"{base} -Protocol {pr} {portarg} " + ",".join(q(x) for x in r["port"].split(",")))
                else:
                    for exe in [e for e in exes if match_path(r["path"], e)] or []:
                        ps.append(f"{base} -Program {q(exe)}")
        res = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "-"],
                             input="\n".join(ps), capture_output=True, text=True, creationflags=0x08000000)
        return res.stderr.strip() or None if res.returncode else None

    # ---------------------------------------------------------------- path rules (nftables)
    def _exe(self, pid, now):
        c = self._exe_cache.get(pid)
        if c and now - c[1] < 30:
            return c[0]
        try:
            exe = psutil.Process(pid).exe()
        except Exception:
            exe = ""
        self._exe_cache[pid] = (exe, now)
        return exe

    def refresh_paths(self, rules):
        """Push the local ports of processes matching each enabled path rule into its set."""
        if self.backend != "nftables":
            return
        prules = [r for r in rules if r["enabled"] and r["kind"] == "path"]
        if not prules:
            return
        now = time.time()
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        want = {r["id"]: set() for r in prules}
        for c in conns:
            if not (c.laddr and c.pid):
                continue
            exe = self._exe(c.pid, now)
            for r in prules:
                if match_path(r["path"], exe):
                    want[r["id"]].add(("tcp" if c.type == socket.SOCK_STREAM else "udp", c.laddr.port))
        if len(self._exe_cache) > 2000:
            self._exe_cache = {k: v for k, v in self._exe_cache.items() if now - v[1] < 30}
        cmds = []
        with self.lock:
            for rid, ports in want.items():
                self.matched[rid] = len(ports)
                if self.pushed.get(rid) == frozenset(ports):
                    continue
                self.pushed[rid] = frozenset(ports)
                cmds.append(f"flush set inet {TABLE} p{rid}")
                if ports:
                    cmds.append(f"add element inet {TABLE} p{rid} {{ " + ", ".join(f"{p} . {n}" for p, n in sorted(ports)) + " }")
            if cmds:
                r = subprocess.run(["nft", "-f", "-"], input="\n".join(cmds) + "\n", capture_output=True, text=True)
                if r.returncode:
                    self.pushed = {}            # table missing/changed: retry next round
                    self.error = r.stderr.strip()[:200]

    # ---------------------------------------------------------------- counters
    def counters(self):
        """-> {rule_id: (packets, bytes)} from nft counters (empty on other backends)."""
        if self.backend != "nftables":
            return {}
        r = subprocess.run(["nft", "-j", "list", "table", "inet", TABLE], capture_output=True, text=True)
        if r.returncode:
            return {}
        out = {}
        for o in json.loads(r.stdout)["nftables"]:
            rule = o.get("rule")
            m = re.fullmatch(r"nw-(\d+)", (rule or {}).get("comment", ""))
            if m:
                for e in rule["expr"]:
                    if "counter" in e:
                        p, b = out.get(int(m[1]), (0, 0))
                        out[int(m[1])] = (p + e["counter"]["packets"], b + e["counter"]["bytes"])
        return out
