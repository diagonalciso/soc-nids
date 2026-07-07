# soc-nids — Network IDS dashboard

Network intrusion detection for the SOC suite. Wraps **Suricata** (the IDS engine)
and gives the SOC a network-visibility pane — Wazuh alone is host-based (HIDS) and
sees nothing on the wire.

- **Engine:** [Suricata](https://suricata.io) — GPLv2, runs as a separate OS daemon.
- **This wrapper:** MIT. Tails Suricata's `eve.json`, keeps rolling counters, serves
  a dark dashboard + JSON API on **:8102**. Pure Python stdlib, no deps.

## How alerts reach the SOC
`install.sh` points **Wazuh's native Suricata decoder** at the same `eve.json`
(a `<localfile>` block in `ossec.conf`), so alerts flow into **soc-ops** automatically.
This service does **not** re-inject them — it only reads `eve.json` for its own
network pane, so there is no double-counting.

```
Suricata (AF_PACKET on IFACE)  ->  /var/log/suricata/eve.json
        |                                   |
        |                                   +-- Wazuh <localfile> json  -> soc-ops queue
        +-- soc-nids tail (this app)  -> :8102 dashboard
```

## Run
```bash
cp .env.example .env          # set NIDS_IFACE, NIDS_HOME_NET
sudo ./install.sh             # install + configure Suricata, wire into Wazuh
env $(grep -v '^#' .env | xargs) python3 app.py
```
Needs a monitoring interface (SPAN/tap/mirror port, or the host's live iface in
promiscuous mode). Set `NIDS_IFACE` accordingly.

## Endpoints
| Path | Purpose |
|------|---------|
| `/` | dashboard |
| `/api/stats` | counters, top signatures/sources, per-minute |
| `/api/alerts` | recent alert ring (JSON) |
| `/health` | status probe (used by soc-hub tile) |

## License
Wrapper: MIT (see `LICENSE`). Suricata is GPLv2 and runs as an independent process —
no linkage, no copyleft obligation on this wrapper.


## Documentation

See **[MANUAL.md](MANUAL.md)** for the full manual (overview, configuration, endpoints, integration, troubleshooting). In the running dashboard, click the **`?` Help button** in the top-right corner to open it at `/manual`.
