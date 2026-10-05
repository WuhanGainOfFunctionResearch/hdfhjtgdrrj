# NetWatch — a small GlassWire-style network monitor

Python backend (stdlib + `psutil`, SQLite storage) and a single-file HTML/JS UI.

```bash
pip install -r requirements.txt
python server.py              # live data, http://127.0.0.1:8765
python server.py --demo       # synthetic data, no privileges needed
```
Run as root/Administrator to see other users' processes (`psutil.net_connections` needs it on most OSes).

## What it does
- **Connections** — per-process TCP/UDP connections, active or full history, with first/last seen and hit counts.
  Click a column header to sort; filter by free text, protocol, public-only remotes, label, or policy; export the filtered view as JSON.
- **Apps** — one row per process with connection/host counts; jump to its connections.
- **Alerts** — raised the first time a new app touches the network, a new public host is contacted, or a connection is made to a target whose policy is `block`.
- **Labels** — click any app name or remote IP to attach a label, colour, note and policy (`trusted` / `watch` / `block`). Stored in SQLite and used by the filters.
- **Traffic graph** — system-wide upload/download throughput (last hour kept in memory).

## Limits (read these)
- Policy `block` is an **advisory flag + alert**; it does not install firewall rules. GlassWire's actual blocking uses the Windows Filtering Platform; on Linux you could add an `iptables`/`nft` call in `POST /api/labels`, on Windows `netsh advfirewall`.
- Throughput is per-interface (system-wide), not per-app. True per-app bandwidth needs packet capture (scapy/libpcap + socket→PID mapping), ETW on Windows, or eBPF on Linux.
- Connections are sampled every 2 s, so very short-lived sockets can be missed.
- The server binds to localhost and has no authentication; don't expose it.

## API
`GET /api/connections?q=&proto=&active=1&remote=public&label=&policy=&sort=&dir=` ·
`GET /api/apps` · `GET /api/alerts` · `GET /api/traffic?since=` ·
`GET|POST|DELETE /api/labels` · `POST /api/alerts/ack`
