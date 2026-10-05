"""Packet-level byte counting for NetWatch (stdlib + psutil only).

Linux   : AF_PACKET raw socket. Needs root or CAP_NET_RAW:
          sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
Windows : one raw IPv4 socket per local address with SIO_RCVALL (no driver, no pcap).
          Needs an elevated (Administrator) terminal. IPv4 only for now.
Other   : not supported.

Only IP headers are parsed; payloads are never stored. Counted bytes are the IP total
length (L2 framing excluded). Results are accumulated per flow
(proto, local_port, remote_ip, remote_port) and drained by the server, which maps local
ports to processes.
"""
import socket, sys, threading, time

import psutil

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
PROTOS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


def create(loopback=False):
    """Pick the capture implementation for this OS."""
    if sys.platform.startswith("win"):
        return WindowsCapture(loopback)
    return LinuxCapture(loopback)


class Capture:
    """Flow table + direction logic shared by every backend."""

    def __init__(self, loopback=False):
        self.loopback = loopback
        self.lock = threading.Lock()
        self.flows = {}          # (proto, lport, raddr, rport) -> [tx, rx]
        self.local_ips = set()
        self.error = None
        self.running = False
        self.packets = 0
        self.bytes = 0

    def start(self):
        raise NotImplementedError

    def drain(self):
        with self.lock:
            f, self.flows = self.flows, {}
        return f

    def _refresh_ips(self):
        ips = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0])
        self.local_ips = ips

    def _account(self, parsed, count_local_pair):
        """parsed = parse_ip() result. count_local_pair: for a packet between two addresses of
        this host, True if this sighting is the one to count (each packet is seen twice)."""
        if not parsed:
            return
        proto, src, sport, dst, dport, length = parsed
        local = self.local_ips
        src_l, dst_l = src in local, dst in local
        with self.lock:
            self.packets += 1
            self.bytes += length
            if src_l and dst_l:                     # loopback / host-to-self
                if not (self.loopback and count_local_pair):
                    return
                self._add((proto, sport, dst, dport), length, 0)
                self._add((proto, dport, src, sport), 0, length)
            elif src_l:
                self._add((proto, sport, dst, dport), length, 0)
            elif dst_l:
                self._add((proto, dport, src, sport), 0, length)

    def _add(self, key, tx, rx):
        f = self.flows.get(key)
        if f is None:
            self.flows[key] = [tx, rx]
        else:
            f[0] += tx; f[1] += rx


# ---------------------------------------------------------------------- Linux
class LinuxCapture(Capture):
    def start(self):
        if not hasattr(socket, "AF_PACKET"):
            self.error = "packet capture is not available on this OS"
            return False
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.settimeout(1.0)
            for opt in ("SO_RCVBUFFORCE", "SO_RCVBUF"):          # bigger kernel buffer: fewer drops in bursts
                try:
                    self.sock.setsockopt(socket.SOL_SOCKET, getattr(socket, opt, 33 if opt == "SO_RCVBUFFORCE" else 8), 64 * 1024 * 1024)
                    break
                except OSError:
                    continue
        except PermissionError:
            self.error = "permission denied: run as root or grant CAP_NET_RAW to python"
            return False
        except OSError as e:
            self.error = f"cannot open packet socket: {e}"
            return False
        self._refresh_ips()
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        return True

    def _loop(self):
        last_refresh = time.time()
        while True:
            try:
                frame, meta = self.sock.recvfrom(65535)
            except socket.timeout:
                frame = None
            except OSError as e:
                self.error, self.running = f"capture stopped: {e}", False
                return
            now = time.time()
            if now - last_refresh > 10:
                self._refresh_ips(); last_refresh = now
            if frame:
                # on lo every packet is seen as outgoing and again as incoming: count the outgoing one
                self._account(parse_frame(frame), meta[2] == PACKET_OUTGOING)


# ---------------------------------------------------------------------- Windows
class WindowsCapture(Capture):
    """SIO_RCVALL sniffing: one raw IPv4 socket bound to each local address sees every IP packet
    to/from that address (both directions). Each socket only counts packets *it* sent for the
    host-to-self case, so nothing is counted twice.

    Not covered: IPv6 (Windows doesn't document whether RCVALL on AF_INET6 includes the header, so
    we don't guess), and anything a VPN/NIC offload hides from the IP layer."""

    def __init__(self, loopback=False):
        super().__init__(loopback)
        self.socks = {}          # local ip -> socket

    def start(self):
        if not hasattr(socket, "SIO_RCVALL"):
            self.error = "this Python has no SIO_RCVALL support"
            return False
        self._refresh_ips()
        self._sync_sockets()
        if not self.socks:
            self.error = self.error or "no IPv4 address could be opened for sniffing"
            return False
        self.running = True
        threading.Thread(target=self._watch_addresses, daemon=True).start()
        return True

    def _ipv4s(self):
        out = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.address != "0.0.0.0" and not a.address.startswith("169.254."):
                    if a.address.startswith("127.") and not self.loopback:
                        continue
                    out.add(a.address)
        return out

    def _sync_sockets(self):
        """Open a sniffer per current IPv4 address; close those that disappeared (Wi-Fi roaming, VPN)."""
        want = self._ipv4s()
        for ip in list(self.socks):
            if ip not in want:
                self._close(ip)
        for ip in want - set(self.socks):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                s.settimeout(1.0)
            except PermissionError:
                self.error = "access denied: start NetWatch from an elevated (Administrator) terminal"
                continue
            except OSError as e:
                self.error = f"cannot sniff {ip}: {e}"
                continue
            self.socks[ip] = s
            threading.Thread(target=self._loop, args=(ip, s), daemon=True).start()

    def _close(self, ip):
        s = self.socks.pop(ip, None)
        if s:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                s.close()
            except OSError:
                pass

    def _watch_addresses(self):
        while True:
            time.sleep(10)
            self._refresh_ips()
            self._sync_sockets()

    def _loop(self, ip, s):
        while self.socks.get(ip) is s:
            try:
                buf, _ = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if self.socks.get(ip) is s:             # not closed on purpose
                    self.error = f"sniffer on {ip} stopped: {e}"
                    self.socks.pop(ip, None)
                return
            p = parse_ip(buf, 0)
            self._account(p, p is not None and p[1] == ip)


# ---------------------------------------------------------------------- parsing
def parse_frame(f):
    """Ethernet frame -> (proto, src, sport, dst, dport, ip_len) or None."""
    if len(f) < 34:
        return None
    et, off = int.from_bytes(f[12:14], "big"), 14
    while et in (0x8100, 0x88A8) and len(f) > off + 4:     # VLAN tags
        et = int.from_bytes(f[off + 2:off + 4], "big"); off += 4
    if et not in (0x0800, 0x86DD):
        return None
    return parse_ip(f, off)


def parse_ip(f, off=0):
    """Raw IPv4/IPv6 packet starting at f[off] -> (proto, src, sport, dst, dport, ip_len) or None."""
    if len(f) < off + 20:
        return None
    ver = f[off] >> 4
    if ver == 4:
        ihl = (f[off] & 15) * 4
        length = int.from_bytes(f[off + 2:off + 4], "big")
        if length == 0:                                     # TSO/LSO: header says 0 until the NIC segments
            length = len(f) - off
        nh = f[off + 9]
        src, dst = socket.inet_ntoa(f[off + 12:off + 16]), socket.inet_ntoa(f[off + 16:off + 20])
        frag = int.from_bytes(f[off + 6:off + 8], "big") & 0x1FFF
        l4 = off + ihl
    elif ver == 6:
        if len(f) < off + 40:
            return None
        length = 40 + int.from_bytes(f[off + 4:off + 6], "big")
        nh = f[off + 6]
        src, dst = socket.inet_ntop(socket.AF_INET6, f[off + 8:off + 24]), socket.inet_ntop(socket.AF_INET6, f[off + 24:off + 40])
        frag, l4 = 0, off + 40
    else:
        return None
    proto = PROTOS.get(nh)
    if not proto:
        return None
    if proto in ("tcp", "udp") and not frag and len(f) >= l4 + 4:
        sport, dport = int.from_bytes(f[l4:l4 + 2], "big"), int.from_bytes(f[l4 + 2:l4 + 4], "big")
    else:
        sport = dport = 0
    return proto, src, sport, dst, dport, length
