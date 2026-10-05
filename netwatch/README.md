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
- **Log analysis** — every executable is recorded the first time a process starts from its path: filename, path, first run time, publisher, signed yes/no (plus run count, last run, user, SHA-256, a "temp/downloads" flag and a "modified" flag if the file changes on disk later). New or unsigned executables raise alerts. Sort, filter (signed / time window / location / text) and export CSV. Windows: Authenticode via PowerShell; macOS: `codesign`; Linux: publisher = owning dpkg/rpm package's maintainer/vendor, "signed" = file still matches the package checksum (so a file in `/tmp` or one you compiled is "no"). Processes already running when NetWatch starts are marked `*`: their first-run time is their start time, earlier runs are unknown.
- **Net protect** — real blocking rules by **port(s)/ranges**, **protocol** (tcp, udp, icmp/ping) or **program / folder / wildcard path**, inbound / outbound / both, each with enable toggle, dropped-packet counter and alerts when a rule starts dropping traffic. "Block" buttons on the Log analysis and Usage pages pre-fill the form. Broad rules (all TCP/UDP, ports 22/53/80/443) ask for confirmation. "Pause all rules" is the panic switch.
- **Traffic graph** — system-wide upload/download throughput (last hour kept in memory).

## Limits (read these)
- Label policy `block` is only an advisory flag + alert; actual blocking is the **Net protect** page.
- Net protect on Linux uses nftables (table `inet netwatch`) and needs root. nftables can't match a program, so a path rule drops the local ports its processes currently own (refreshed every 0.5 s): an existing connection is cut within ~0.5 s, but a brand-new connection can leak its first packet(s). Processes are matched by exact exe path, so a program that re-launches itself from a different path isn't covered.
- Net protect on Windows (PowerShell `New-NetFirewallRule`, needs Administrator) is implemented but **untested**; macOS is not supported (rules are stored, not enforced).
- Rules are removed when NetWatch exits cleanly (fail-open, so a stopped monitor can't lock you out) and re-applied on start. After a hard kill run `sudo nft delete table inet netwatch`.
- Per-app bandwidth is **Linux only** (AF_PACKET) and needs root/CAP_NET_RAW. macOS/Windows would need pcap/ETW. Without it the Usage tab shows a notice and everything else still works.
- Connections that open and close between two 2-second samples can't be matched to a process; their bytes appear under `(unattributed)`. Counts are IP-layer bytes (headers included, Ethernet framing excluded). Python parsing is fine for home-scale traffic but not multi-gigabit.
- With `--loopback`, a local client↔server pair is counted on both ends.
- Connections are sampled every 2 s, so very short-lived sockets can be missed.
- The server binds to localhost and has no authentication; don't expose it.

## API
`GET /api/connections?q=&proto=&active=1&remote=public&label=&policy=&sort=&dir=` ·
`GET /api/usage?range=&group=app|app_port|port|proto&proto=&q=&sort=&dir=` · `GET /api/usage/series` · `GET /api/usage/live` · `GET /api/capture` ·
`GET /api/executables[.csv]?q=&signed=yes|no|pending&since=&risky=1&sort=&dir=` ·
`GET /api/protect` · `POST /api/protect/rules|toggle|master` · `DELETE /api/protect/rules?id=` ·
`GET /api/apps` · `GET /api/alerts` · `GET /api/traffic?since=` ·
`GET|POST|DELETE /api/labels` · `POST /api/alerts/ack`
