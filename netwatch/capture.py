"""Packet-level byte counting for NetWatch (Linux, AF_PACKET, stdlib only).

Needs root or CAP_NET_RAW:  sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
Only IP headers are parsed; payloads are never stored. Counted bytes are IP
total length (L2 framing excluded). Results are accumulated per flow
(proto, local_port, remote_ip, remote_port) and drained by the server, which
maps local ports to processes.
"""
import socket, threading, time

import psutil

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
PROTOS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


class Capture:
    def __init__(self, loopback=True):
        self.loopback = loopback
        self.lock = threading.Lock()
        self.flows = {}          # (proto, lport, raddr, rport) -> [tx, rx]
        self.local_ips = set()
        self.error = None
        self.running = False
        self.packets = 0
        self.bytes = 0

    # -------------------------------------------------------------- control
    def start(self):
        if not hasattr(socket, "AF_PACKET"):
            self.error = "packet capture needs Linux (AF_PACKET); not available on this OS"
            return False
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.settimeout(1.0)
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

    # -------------------------------------------------------------- capture
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
                self._packet(frame, meta[2])

    def _packet(self, frame, pkttype):
        p = parse_frame(frame)
        if not p:
            return
        proto, src, sport, dst, dport, length = p
        local = self.local_ips
        src_l, dst_l = src in local, dst in local
        with self.lock:
            self.packets += 1
            self.bytes += length
            if src_l and dst_l:                     # loopback / host-to-self
                if not self.loopback or pkttype != PACKET_OUTGOING:
                    return                          # each packet is seen twice on lo
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


def parse_frame(f):
    """-> (proto, src, sport, dst, dport, ip_len) or None."""
    if len(f) < 34:
        return None
    et, off = int.from_bytes(f[12:14], "big"), 14
    while et in (0x8100, 0x88A8) and len(f) > off + 4:     # VLAN tags
        et = int.from_bytes(f[off + 2:off + 4], "big"); off += 4
    if et == 0x0800:
        ihl = (f[off] & 15) * 4
        length = int.from_bytes(f[off + 2:off + 4], "big")
        nh = f[off + 9]
        src, dst = socket.inet_ntoa(f[off + 12:off + 16]), socket.inet_ntoa(f[off + 16:off + 20])
        frag = int.from_bytes(f[off + 6:off + 8], "big") & 0x1FFF
        l4 = off + ihl
    elif et == 0x86DD:
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
