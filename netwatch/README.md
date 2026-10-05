# NetWatch — a small GlassWire-style network monitor

Python backend (stdlib + `psutil`, SQLite storage) and a single-file HTML/JS UI.

```bash
pip install -r requirements.txt
python server.py              # live data, http://127.0.0.1:8765
python server.py --demo       # synthetic data, no privileges needed
```
Run as root to see other users' processes and to enable per-app bandwidth (packet capture needs `CAP_NET_RAW`):
`sudo python server.py`, or `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))` once.
Flags: `--no-capture` (connections only), `--loopback` (also count 127.0.0.1 traffic), `--port`, `--host`.

## What it does
- **Connections** — per-process TCP/UDP connections, active or full history, with first/last seen and hit counts.
  Click a column header to sort; filter by free text, protocol, public-only remotes, label, or policy; export the filtered view as JSON.
- **Apps** — one row per process with connection/host counts; jump to its connections.
- **Alerts** — raised the first time a new app touches the network, a new public host is contacted, or a connection is made to a target whose policy is `block`.
- **Labels** — click any app name or remote IP to attach a label, colour, note and policy (`trusted` / `watch` / `block`). Stored in SQLite and used by the filters.
- **Usage (per-app bandwidth)** — bytes sent/received per app, protocol (tcp/udp/icmp) and port, with the service name
  (443 → https). Pick a range (5 min – 30 days), group by app / app+port / port / protocol, filter, sort any column.
  Includes a live per-app rate table and a stacked chart of the top apps. History is kept in 1-minute buckets for 30 days.
  How: `capture.py` reads IP headers from an `AF_PACKET` socket (payloads are never stored), counts bytes per flow,
  and the server maps local ports to processes via `psutil`. "Port" is the service port: the listening port for
  inbound traffic, otherwise the remote port.
- **Traffic graph** — system-wide upload/download throughput (last hour kept in memory).

## Limits (read these)
- Policy `block` is an **advisory flag + alert**; it does not install firewall rules. GlassWire's actual blocking uses the Windows Filtering Platform; on Linux you could add an `iptables`/`nft` call in `POST /api/labels`, on Windows `netsh advfirewall`.
- Per-app bandwidth is **Linux only** (AF_PACKET) and needs root/CAP_NET_RAW. macOS/Windows would need pcap/ETW. Without it the Usage tab shows a notice and everything else still works.
- Connections that open and close between two 2-second samples can't be matched to a process; their bytes appear under `(unattributed)`. Counts are IP-layer bytes (headers included, Ethernet framing excluded). Python parsing is fine for home-scale traffic but not multi-gigabit.
- With `--loopback`, a local client↔server pair is counted on both ends.
- Connections are sampled every 2 s, so very short-lived sockets can be missed.
- The server binds to localhost and has no authentication; don't expose it.

## API
`GET /api/connections?q=&proto=&active=1&remote=public&label=&policy=&sort=&dir=` ·
`GET /api/usage?range=&group=app|app_port|port|proto&proto=&q=&sort=&dir=` · `GET /api/usage/series` · `GET /api/usage/live` · `GET /api/capture` ·
`GET /api/apps` · `GET /api/alerts` · `GET /api/traffic?since=` ·
`GET|POST|DELETE /api/labels` · `POST /api/alerts/ack`
