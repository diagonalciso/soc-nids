#!/usr/bin/env python3
"""soc-nids — network IDS dashboard (Suricata sidecar).

Suricata (GPLv2) runs as a separate OS daemon and writes eve.json. This wrapper
(MIT) tails eve.json, keeps rolling counters in memory, and serves a small dark
dashboard + JSON API. It does NOT re-inject into Wazuh — install.sh points Wazuh's
native Suricata decoder at the same eve.json (a <localfile> block in ossec.conf),
so alerts already flow to soc-ops. This UI is the network-visibility pane.

Run: cp .env.example .env && env $(grep -v '^#' .env | xargs) python3 app.py
"""
import json
import os
import threading
import time
from collections import deque, Counter
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

EVE_JSON = os.getenv("EVE_JSON", "/var/log/suricata/eve.json")
IFACE = os.getenv("NIDS_IFACE", "eth0")
HOME_NET = os.getenv("NIDS_HOME_NET", "10.10.0.0/16")
PORT = int(os.getenv("NIDS_PORT", "8102"))
HOST = os.getenv("NIDS_HOST", "0.0.0.0")
RING = int(os.getenv("NIDS_RING", "500"))

# --------------------------------------------------------------------------- #
# Shared state
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_alerts = deque(maxlen=RING)          # recent alert events (dicts)
_by_sig = Counter()                   # signature -> count
_by_src = Counter()                   # src_ip -> count
_by_sev = Counter()                   # severity(1-3) -> count
_per_min = deque(maxlen=60)           # (minute_epoch, count) last hour
_state = {"total": 0, "file_seen": False, "started": time.time(),
          "last_ts": None}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _bump_minute():
    m = int(time.time() // 60)
    if _per_min and _per_min[-1][0] == m:
        _per_min[-1][1] += 1
    else:
        _per_min.append([m, 1])


def _ingest(ev):
    """Handle one parsed eve.json line; keep only alert events."""
    if ev.get("event_type") != "alert":
        return
    a = ev.get("alert", {})
    rec = {
        "ts": ev.get("timestamp", _now_iso()),
        "src_ip": ev.get("src_ip", "?"),
        "src_port": ev.get("src_port"),
        "dest_ip": ev.get("dest_ip", "?"),
        "dest_port": ev.get("dest_port"),
        "proto": ev.get("proto", "?"),
        "signature": a.get("signature", "?"),
        "category": a.get("category", ""),
        "severity": a.get("severity", 3),
    }
    with _lock:
        _alerts.appendleft(rec)
        _by_sig[rec["signature"]] += 1
        _by_src[rec["src_ip"]] += 1
        _by_sev[rec["severity"]] += 1
        _bump_minute()
        _state["total"] += 1
        _state["last_ts"] = rec["ts"]


# --------------------------------------------------------------------------- #
# Tailer — follows eve.json, survives rotation/truncation, waits if absent
# --------------------------------------------------------------------------- #
def _tailer():
    pos = 0
    inode = None
    while True:
        try:
            st = os.stat(EVE_JSON)
        except OSError:
            with _lock:
                _state["file_seen"] = False
            time.sleep(3)
            continue
        with _lock:
            _state["file_seen"] = True
        if inode != st.st_ino:          # first open or rotated
            inode = st.st_ino
            pos = 0
        if st.st_size < pos:            # truncated
            pos = 0
        try:
            with open(EVE_JSON, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        _ingest(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                pos = f.tell()
        except OSError:
            pass
        time.sleep(1)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _stats():
    with _lock:
        eps = sum(c for _, c in list(_per_min)[-5:]) / 5.0
        return {
            "total": _state["total"],
            "file_seen": _state["file_seen"],
            "eve_json": EVE_JSON,
            "iface": IFACE,
            "home_net": HOME_NET,
            "last_ts": _state["last_ts"],
            "uptime_s": int(time.time() - _state["started"]),
            "alerts_per_min": round(eps, 1),
            "sev": {str(k): v for k, v in sorted(_by_sev.items())},
            "top_signatures": _by_sig.most_common(10),
            "top_sources": _by_src.most_common(10),
            "per_min": list(_per_min),
        }


def _recent(n=100):
    with _lock:
        return list(_alerts)[:n]


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC NIDS — Network IDS</title><style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--txt:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--crit:#f85149;--hi:#f0883e;--med:#d29922}
*{box-sizing:border-box}body{margin:0;font-family:'JetBrains Mono',ui-monospace,monospace;background:var(--bg);color:var(--txt)}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;border-bottom:1px solid var(--bd);background:var(--panel)}
h1{margin:0;font-size:18px;letter-spacing:1px;color:var(--accent)}
h1 small{font-weight:400;opacity:.55;font-size:.6em;color:var(--txt)}
.meta{font-size:12px;color:var(--dim);text-align:right;line-height:1.5}
.wrap{max-width:1200px;margin:0 auto;padding:20px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:14px}
.kpi .n{font-size:26px;font-weight:700;color:var(--accent)}
.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:14px}
.panel h2{margin:0 0 10px;font-size:13px;color:var(--accent);letter-spacing:1px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);white-space:nowrap}
th{color:var(--dim);font-weight:600}
tr td .bar{display:inline-block;height:6px;background:var(--accent);border-radius:3px;vertical-align:middle}
.sev1{color:var(--crit)}.sev2{color:var(--hi)}.sev3{color:var(--med)}
.full{grid-column:1/-1}
.warn{background:#2a1a00;border-color:#5a3a00;color:var(--hi);padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
.dim{color:var(--dim)}
</style></head><body><a href="/manual" target="_blank" title="Manual / Help" style="position:fixed;top:12px;right:14px;z-index:99999;width:30px;height:30px;border-radius:50%;background:#161b22;border:1px solid #30363d;color:#58a6ff;font:700 16px/30px system-ui,sans-serif;text-align:center;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.4)" onmouseover="this.style.borderColor='#58a6ff'" onmouseout="this.style.borderColor='#30363d'">?</a>
<header>
  <h1>SOC-NIDS <small>Network IDS · Suricata</small></h1>
  <div class="meta" id="meta">connecting…</div>
</header>
<div class="wrap">
  <div id="filewarn"></div>
  <div class="kpis">
    <div class="kpi"><div class="n" id="k-total">--</div><div class="l">Alerts total</div></div>
    <div class="kpi"><div class="n" id="k-epm">--</div><div class="l">Alerts / min</div></div>
    <div class="kpi"><div class="n sev1" id="k-crit">--</div><div class="l">Severity 1 (crit)</div></div>
    <div class="kpi"><div class="n" id="k-src">--</div><div class="l">Unique sources</div></div>
  </div>
  <div class="grid">
    <div class="panel"><h2>Top Signatures</h2><table id="t-sig"><tbody><tr><td class="dim">awaiting…</td></tr></tbody></table></div>
    <div class="panel"><h2>Top Source IPs</h2><table id="t-src"><tbody><tr><td class="dim">awaiting…</td></tr></tbody></table></div>
    <div class="panel full"><h2>Live Alert Stream</h2>
      <table id="t-stream"><thead><tr><th>Time</th><th>Sev</th><th>Signature</th><th>Src</th><th>Dst</th><th>Proto</th></tr></thead>
      <tbody><tr><td colspan="6" class="dim">awaiting alerts…</td></tr></tbody></table>
    </div>
  </div>
</div>
<script>
const $=s=>document.querySelector(s);
async function poll(){
  try{
    const st=await (await fetch('/api/stats')).json();
    const al=await (await fetch('/api/alerts')).json();
    $('#k-total').textContent=st.total;
    $('#k-epm').textContent=st.alerts_per_min;
    $('#k-crit').textContent=st.sev['1']||0;
    $('#k-src').textContent=st.top_sources.length;
    $('#meta').innerHTML=`iface <b>${st.iface}</b> · home ${st.home_net}<br>${st.eve_json}<br>last: ${st.last_ts||'—'}`;
    $('#filewarn').innerHTML = st.file_seen ? '' :
      `<div class="warn">⚠ eve.json not found at <b>${st.eve_json}</b> — Suricata not running yet? See install.sh.</div>`;
    const max=(st.top_signatures[0]||[,1])[1]||1;
    $('#t-sig').innerHTML='<tbody>'+(st.top_signatures.map(([s,c])=>
      `<tr><td>${esc(s)}</td><td style="text-align:right">${c}</td><td style="width:90px"><span class="bar" style="width:${Math.round(80*c/max)}px"></span></td></tr>`).join('')||'<tr><td class="dim">none</td></tr>')+'</tbody>';
    $('#t-src').innerHTML='<tbody>'+(st.top_sources.map(([s,c])=>
      `<tr><td>${esc(s)}</td><td style="text-align:right">${c}</td></tr>`).join('')||'<tr><td class="dim">none</td></tr>')+'</tbody>';
    $('#t-stream').querySelector('tbody').innerHTML = al.length? al.map(a=>
      `<tr><td>${esc((a.ts||'').replace('T',' ').slice(0,19))}</td><td class="sev${a.severity}">${a.severity}</td><td>${esc(a.signature)}</td><td>${esc(a.src_ip)}:${a.src_port||''}</td><td>${esc(a.dest_ip)}:${a.dest_port||''}</td><td>${esc(a.proto)}</td></tr>`
      ).join('') : '<tr><td colspan="6" class="dim">no alerts yet</td></tr>';
  }catch(e){$('#meta').textContent='poll error';}
}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
poll();setInterval(poll,4000);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        if self.path.split("?")[0].rstrip("/") == "/manual":
            _serve_manual(self); return
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        elif self.path == "/api/stats":
            self._send(200, "application/json", json.dumps(_stats()))
        elif self.path.startswith("/api/alerts"):
            self._send(200, "application/json", json.dumps(_recent()))
        elif self.path == "/health":
            self._send(200, "application/json",
                       json.dumps({"status": "ok", "file_seen": _state["file_seen"],
                                   "total": _state["total"]}))
        else:
            self._send(404, "text/plain", "not found")

    def log_message(self, *a):
        pass




# ---- injected: /manual help page (stdlib markdown renderer) ----------------
def _md_to_html(md):
    import html, re as _re
    lines = md.split("\n")
    out = []; i = 0; n = len(lines)
    def inline(t):
        t = html.escape(t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        t = _re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                    r'<a href="\2" target="_blank" rel="noopener">\1</a>', t)
        return t
    while i < n:
        ln = lines[i]
        if ln.startswith("```"):
            i += 1; buf = []
            while i < n and not lines[i].startswith("```"):
                buf.append(html.escape(lines[i])); i += 1
            i += 1
            out.append("<pre><code>" + "\n".join(buf) + "</code></pre>"); continue
        m = _re.match(r"(#{1,6})\s+(.*)", ln)
        if m:
            lv = len(m.group(1)); out.append("<h%d>%s</h%d>" % (lv, inline(m.group(2)), lv)); i += 1; continue
        if _re.match(r"\s*[-*]\s+", ln):
            out.append("<ul>")
            while i < n and _re.match(r"\s*[-*]\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*[-*]\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ul>"); continue
        if _re.match(r"\s*\d+\.\s+", ln):
            out.append("<ol>")
            while i < n and _re.match(r"\s*\d+\.\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*\d+\.\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ol>"); continue
        if ln.strip().startswith("|") and i + 1 < n and _re.match(r"^\s*\|[-:\s|]+\|\s*$", lines[i+1]):
            hdr = [c.strip() for c in ln.strip().strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join("<th>%s</th>" % inline(c) for c in hdr) + "</tr></thead><tbody>")
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in cells) + "</tr>"); i += 1
            out.append("</tbody></table>"); continue
        if _re.match(r"^\s*---+\s*$", ln):
            out.append("<hr>"); i += 1; continue
        if ln.strip() == "":
            i += 1; continue
        para = [ln]; i += 1
        while i < n and lines[i].strip() and not _re.match(r"(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s|\|)", lines[i]):
            para.append(lines[i]); i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")
    return "\n".join(out)


def _manual_page(inner):
    return ("""<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Manual</title><style>
:root{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--ac:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:15px/1.65 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 22px 80px}
.top{position:sticky;top:0;background:rgba(13,17,23,.92);backdrop-filter:blur(6px);
border-bottom:1px solid var(--bd);margin:-32px -22px 24px;padding:12px 22px;display:flex;
align-items:center;gap:12px}
.top a{color:var(--ac);text-decoration:none;font-size:13px}
h1,h2,h3,h4{color:#fff;line-height:1.25;margin:1.5em 0 .5em}
h1{font-size:26px;border-bottom:1px solid var(--bd);padding-bottom:.3em}
h2{font-size:20px;border-bottom:1px solid var(--bd);padding-bottom:.25em}
h3{font-size:16px}a{color:var(--ac)}
code{background:var(--sf);border:1px solid var(--bd);border-radius:4px;padding:1px 5px;
font:13px/1.4 ui-monospace,Menlo,monospace}
pre{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;
overflow:auto}pre code{background:none;border:0;padding:0}
ul,ol{padding-left:1.4em}li{margin:.25em 0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:14px}
th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left}
th{background:var(--sf)}hr{border:0;border-top:1px solid var(--bd);margin:2em 0}
.mut{color:var(--mut)}
</style></head><body><div class=wrap>
<div class=top><a href="/">&larr; Back to app</a><span class=mut>&middot; Manual</span></div>
""" + inner + "\n</div></body></html>")


def _serve_manual(handler):
    import os as _os
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "MANUAL.md")
    try:
        with open(p, encoding="utf-8") as _fh:
            md = _fh.read()
    except OSError:
        md = "# Manual\n\nMANUAL.md not found next to the application."
    body = _manual_page(_md_to_html(md)).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
# ---- end injected block -----------------------------------------------------

if __name__ == "__main__":
    threading.Thread(target=_tailer, daemon=True).start()
    print(f"soc-nids on http://{HOST}:{PORT}  (eve.json={EVE_JSON})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
