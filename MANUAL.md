# soc-NIDS — Network Intrusion Detection Dashboard

> Suricata eve.json live dashboard for the SOC suite.

**Port:** `8102` &nbsp;|&nbsp; **Repo:** `diagonalciso/soc-nids` &nbsp;|&nbsp; **Service:** `soc-nids.service` &nbsp;|&nbsp; **Stack:** stdlib Python (no external deps)

Part of the **CD / Wazuh Full SOC** suite. Open the in-app **`?` Help button** (top-right of the dashboard) to read this manual, or view it here.

---

## 1. Overview

soc-NIDS gives the host-centric Wazuh SOC the network visibility it otherwise lacks. Suricata (running as a standalone OS service on a SPAN/tap or inline interface) writes alerts to `/var/log/suricata/eve.json`; soc-NIDS tails that file and renders a live operational picture — alert rate, top signatures, top talkers, and interface health. Wazuh ingests the same eve.json via its native Suricata decoder, so alerts also flow into soc-ops for triage. soc-NIDS never re-parses into Wazuh — it is a read-only lens, avoiding double-counting.

## 2. Key features

- Live tail of Suricata `eve.json` with alerts-per-minute rate
- Top signatures and top source IPs over the current window
- Monitored-interface status and a warning if the eve.json file is not being written
- One-click `suricata-update` ruleset refresh + rule reload (when enabled)
- Feeds attacker source IPs to soc-threatmap

## 3. Running the service

The service is a single self-contained `app.py` using only the Python standard library.

```bash
# systemd (fleet / suite install)
sudo systemctl status soc-nids
sudo systemctl restart soc-nids
sudo journalctl -u soc-nids -f

# manual run (from the repo directory)
cp .env.example .env      # then edit as needed
env $(grep -v '^#' .env | xargs) python3 app.py
```

Then open **http://<host>:8102/**.

## 4. Configuration (environment variables)

Set these in `.env` (see `.env.example` for defaults):

| Variable | Notes |
|---|---|
| `EVE_JSON` |  |
| `NIDS_HOME_NET` |  |
| `NIDS_HOST` |  |
| `NIDS_IFACE` |  |
| `NIDS_PORT` | Listen port (default 8102). |
| `NIDS_RING` |  |

## 5. HTTP endpoints

| Path | |
|---|---|
| `/` | Main dashboard (HTML) |
| `/api/alerts` | API endpoint (JSON) |
| `/api/stats` | API endpoint (JSON) |
| `/health` | Health check |
| `/manual` | This manual (opened by the top-right **?** Help button) |

## 6. Integration

Wazuh reads the same eve.json (native Suricata decoder) → alerts land in soc-ops. Source IPs can be forwarded to soc-threatmap for the live attack map.

## 7. Security & operational notes

Read-only. Requires a Suricata install and a monitor interface (SPAN/tap or AF_PACKET). Rule updates run only if the wrapper is granted permission to invoke suricata-update.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Page will not load | `systemctl status soc-nids`; confirm the port `8102` is listening (`lsof -i:8102`). |
| Help button shows "MANUAL.md not found" | Ensure `MANUAL.md` sits next to `app.py` in the service directory. |
| Service keeps restarting | `journalctl -u soc-nids -e` for the traceback; usually a missing `.env` value. |
| Empty / stale data | Confirm upstream sources and any API keys in `.env` are reachable. |

---

*Manual for soc-nids. Part of the CD / Wazuh Full SOC suite. Private © CisoDiagonal.*
