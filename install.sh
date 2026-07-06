#!/usr/bin/env bash
# soc-nids installer — Suricata (GPLv2 daemon) + wire eve.json into Wazuh + this dashboard.
# Run as root on the SOC host. Idempotent-ish; safe to re-run.
set -euo pipefail

IFACE="${NIDS_IFACE:-eth0}"
HOME_NET="${NIDS_HOME_NET:-10.10.0.0/16}"
OSSEC_CONF="${OSSEC_CONF:-/var/ossec/etc/ossec.conf}"

echo "[soc-nids] installing Suricata…"
if ! command -v suricata >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y suricata jq
fi

echo "[soc-nids] fetching ruleset (ET Open) via suricata-update…"
suricata-update || echo "[soc-nids] suricata-update failed (offline?) — continuing"

echo "[soc-nids] setting HOME_NET=${HOME_NET} and AF_PACKET iface=${IFACE}…"
# Minimal in-place edits; review /etc/suricata/suricata.yaml for anything custom.
sed -i "s#^\(\s*HOME_NET:\).*#\1 \"[${HOME_NET}]\"#" /etc/suricata/suricata.yaml || true
sed -i "s#^\(\s*- interface:\).*#\1 ${IFACE}#" /etc/suricata/suricata.yaml || true

echo "[soc-nids] enabling Suricata service…"
systemctl enable --now suricata || true
systemctl restart suricata || true

# --- Wire eve.json into Wazuh's native Suricata decoder (no double-parsing here) ---
if [ -f "$OSSEC_CONF" ] && ! grep -q "/var/log/suricata/eve.json" "$OSSEC_CONF"; then
  echo "[soc-nids] adding Suricata eve.json localfile to Wazuh ossec.conf…"
  # insert before the closing </ossec_config>
  BLOCK='  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/suricata/eve.json</location>\n  </localfile>'
  sed -i "s#</ossec_config>#${BLOCK}\n</ossec_config>#" "$OSSEC_CONF"
  systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart || true
else
  echo "[soc-nids] Wazuh ossec.conf not found or already wired — skipping."
fi

echo "[soc-nids] done. Suricata -> /var/log/suricata/eve.json ; dashboard: python3 app.py (:8102)."
