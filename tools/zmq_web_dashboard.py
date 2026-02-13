#!/usr/bin/env python3
# Copyright 2025-2026 CEMAXECUTER LLC
"""
Live web dashboard for ice9-bluetooth-sniffer ZMQ streams.

Connects to one or more ZMQ PUB endpoints and displays captured BLE packets
in a real-time web interface. Features a privacy toggle to mask MAC addresses
(useful for video recording / streaming).

Usage:
    # Basic - connect to local sensor:
    python3 zmq_web_dashboard.py tcp://localhost:5555

    # Multiple sensors:
    python3 zmq_web_dashboard.py tcp://sensor1:5555 tcp://sensor2:5555

    # Custom port:
    python3 zmq_web_dashboard.py tcp://localhost:5555 --port 8080

    # With GPS map:
    python3 zmq_web_dashboard.py tcp://sensor:5555 --gps

    # Encrypted connection:
    python3 zmq_web_dashboard.py tcp://sensor:5555 --server-key server.key.pub

    # Also write PCAP while viewing dashboard:
    python3 zmq_web_dashboard.py tcp://localhost:5555 -w capture.pcap --gps

Requirements:
    pip install pyzmq
"""

import argparse
import json
import queue
import signal
import struct
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

try:
    import zmq
except ImportError:
    print("pyzmq is required: pip install pyzmq", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# BLE / PCAP structures (matching pcap.c / zmq_subscriber.py)
# ---------------------------------------------------------------------------
PCAP_GLOBAL_HDR = struct.Struct("<IHHiIII")
PCAP_REC_HDR = struct.Struct("<IIII")
BLE_RF_HDR = struct.Struct("<bbbBIH")
ZMQ_GPS_FRAME = struct.Struct("<ddd")

LE_DEWHITENED         = 0x0001
LE_SIGNAL_POWER_VALID = 0x0002
LE_NOISE_POWER_VALID  = 0x0004
LE_CRC_CHECKED        = 0x0400
LE_CRC_VALID          = 0x0800

BLE_ADV_AA = 0x8E89BED6

# PPI structures for GPS PCAP writing
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_PPI = 192
PPI_HDR = struct.Struct("<BBHI")
PPI_FIELD_HDR = struct.Struct("<HH")
PPI_GPS = struct.Struct("<BBHIIIII")
PPI_FIELD_GPS = 30002
PPI_GPS_FLAG_GPSFLAGS = 0x00000001
PPI_GPS_FLAG_LAT      = 0x00000002
PPI_GPS_FLAG_LON      = 0x00000004
PPI_GPS_FLAG_ALT      = 0x00000008
PPI_HDR_SIZE = PPI_HDR.size
PPI_GPS_SIZE = PPI_HDR.size + PPI_FIELD_HDR.size + PPI_GPS.size


def ppi_fixed3_7(val):
    return int((val + 180.0) * 1e7)

def ppi_fixed6_4(val):
    return int((val + 180000.0) * 1e4)

def build_ppi_gps_header(lat, lon, alt):
    ppi_hdr = PPI_HDR.pack(0, 0, PPI_GPS_SIZE, DLT_BLUETOOTH_LE_LL_WITH_PHDR)
    fld_hdr = PPI_FIELD_HDR.pack(PPI_FIELD_GPS, PPI_GPS.size)
    gps_data = PPI_GPS.pack(
        2, 0, PPI_GPS.size,
        PPI_GPS_FLAG_GPSFLAGS | PPI_GPS_FLAG_LAT | PPI_GPS_FLAG_LON | PPI_GPS_FLAG_ALT,
        0, ppi_fixed3_7(lat), ppi_fixed3_7(lon), ppi_fixed6_4(alt),
    )
    return ppi_hdr + fld_hdr + gps_data

def build_ppi_passthrough_header():
    return PPI_HDR.pack(0, 0, PPI_HDR_SIZE, DLT_BLUETOOTH_LE_LL_WITH_PHDR)


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------
def channel_to_freq(ch):
    return 2402 + ch * 2


def extract_mac(ble_data, aa):
    """Extract advertiser MAC from BLE advertising PDU."""
    if aa != BLE_ADV_AA:
        return None
    # AA(4) + Header(2) + AdvA(6)
    if len(ble_data) < 12:
        return None
    mac_bytes = ble_data[6:12]
    return ":".join(f"{b:02x}" for b in reversed(mac_bytes))


def parse_ble_packet(data):
    """Parse a ZMQ message containing a PCAP record."""
    if len(data) < PCAP_REC_HDR.size + BLE_RF_HDR.size:
        return None

    ts_sec, ts_usec, incl_len, orig_len = PCAP_REC_HDR.unpack_from(data, 0)
    offset = PCAP_REC_HDR.size

    rf_channel, signal_power, noise_power, aa_offenses, ref_aa, flags = \
        BLE_RF_HDR.unpack_from(data, offset)
    offset += BLE_RF_HDR.size

    ble_data = data[offset:]
    aa = struct.unpack_from("<I", ble_data, 0)[0] if len(ble_data) >= 4 else 0

    crc_checked = bool(flags & LE_CRC_CHECKED)
    crc_valid = bool(flags & LE_CRC_VALID) if crc_checked else None
    is_adv = (aa == BLE_ADV_AA)
    mac = extract_mac(ble_data, aa)

    # Extract PDU type for advertising packets
    pdu_type = None
    pdu_type_name = None
    if is_adv and len(ble_data) >= 6:
        pdu_type = ble_data[4] & 0x0F
        pdu_names = {
            0: "ADV_IND", 1: "ADV_DIRECT", 2: "ADV_NONCONN",
            3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND",
            6: "ADV_SCAN_IND",
        }
        pdu_type_name = pdu_names.get(pdu_type, f"ADV_{pdu_type}")

    return {
        "timestamp": ts_sec + ts_usec / 1e6,
        "rf_channel": rf_channel,
        "freq_mhz": channel_to_freq(rf_channel),
        "signal_power": signal_power,
        "noise_power": noise_power,
        "aa": aa,
        "flags": flags,
        "crc_checked": crc_checked,
        "crc_valid": crc_valid,
        "is_adv": is_adv,
        "pdu_type": pdu_type_name or ("ADV" if is_adv else "DATA"),
        "mac": mac,
        "data_len": len(ble_data),
    }


# ---------------------------------------------------------------------------
# Shared dashboard state (device-centric, Kismet-style)
# ---------------------------------------------------------------------------
class DashboardState:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_packets = 0
        self.crc_valid = 0
        self.crc_invalid = 0
        self.data_packets = 0
        self.gps_count = 0
        self.last_gps = None
        self.start_time = time.time()
        self.sse_queues = []
        # Device table: mac -> device info dict
        self.devices = {}
        self._dirty = True

    def add_packet(self, pkt, gps_info=None):
        with self.lock:
            self.total_packets += 1
            if pkt["crc_checked"]:
                if pkt["crc_valid"]:
                    self.crc_valid += 1
                else:
                    self.crc_invalid += 1
            if gps_info:
                self.gps_count += 1
                self.last_gps = gps_info

            mac = pkt["mac"]
            if not mac:
                self.data_packets += 1
                return

            now = round(pkt["timestamp"], 6)
            if mac in self.devices:
                d = self.devices[mac]
                d["pkts"] += 1
                d["last"] = now
                d["freq"] = pkt["freq_mhz"]
                if pkt["signal_power"] > d["rssi"]:
                    d["rssi"] = pkt["signal_power"]
                d["type"] = pkt["pdu_type"]
                if pkt["crc_valid"]:
                    d["crc_ok"] += 1
                elif pkt["crc_valid"] is False:
                    d["crc_bad"] += 1
                if gps_info:
                    d["lat"] = round(gps_info[0], 6)
                    d["lon"] = round(gps_info[1], 6)
            else:
                d = {
                    "mac": mac,
                    "first": now,
                    "last": now,
                    "freq": pkt["freq_mhz"],
                    "rssi": pkt["signal_power"],
                    "type": pkt["pdu_type"],
                    "pkts": 1,
                    "crc_ok": 1 if pkt["crc_valid"] else 0,
                    "crc_bad": 1 if pkt["crc_valid"] is False else 0,
                }
                if gps_info:
                    d["lat"] = round(gps_info[0], 6)
                    d["lon"] = round(gps_info[1], 6)
                self.devices[mac] = d
            self._dirty = True

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            crc_total = self.crc_valid + self.crc_invalid
            return {
                "total": self.total_packets,
                "rate": round(self.total_packets / max(elapsed, 0.001), 1),
                "crc_pct": round(100.0 * self.crc_valid / crc_total, 1) if crc_total > 0 else None,
                "crc_valid": self.crc_valid,
                "crc_invalid": self.crc_invalid,
                "macs": len(self.devices),
                "data_pkts": self.data_packets,
                "gps_count": self.gps_count,
                "last_gps": list(self.last_gps[:2]) if self.last_gps else None,
                "uptime": round(elapsed, 1),
            }

    def get_devices(self):
        """Return device list sorted by last-seen (most recent first)."""
        with self.lock:
            self._dirty = False
            devs = sorted(self.devices.values(), key=lambda d: d["last"], reverse=True)
            return devs

    def is_dirty(self):
        with self.lock:
            return self._dirty

    def register_sse(self):
        q = queue.Queue(maxsize=50)
        with self.lock:
            self.sse_queues.append(q)
        return q

    def unregister_sse(self, q):
        with self.lock:
            if q in self.sse_queues:
                self.sse_queues.remove(q)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
state = DashboardState()
gps_enabled = False


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._serve_html()
        elif path == "/events":
            self._serve_sse()
        elif path == "/api/stats":
            self._serve_json(state.get_stats())
        elif path == "/api/devices":
            self._serve_json(state.get_devices())
        else:
            self.send_error(404)

    def _serve_html(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = DASHBOARD_HTML.replace("__GPS_ENABLED__", "true" if gps_enabled else "false")
        self.wfile.write(html.encode())

    def _serve_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q = state.register_sse()
        try:
            while running:
                time.sleep(1.0)
                # Push full device list + stats once per second
                devs = state.get_devices()
                stats = state.get_stats()
                payload = json.dumps({"stats": stats, "devices": devs})
                self.wfile.write(f"event: update\ndata: {payload}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        finally:
            state.unregister_sse(q)

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# ZMQ receiver thread
# ---------------------------------------------------------------------------
running = True


def zmq_receiver(endpoints, server_key_path, pcap_file, use_gps, bind_mode=False):
    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.setsockopt(zmq.SUBSCRIBE, b"")
    sub.setsockopt(zmq.RCVTIMEO, 1000)

    if server_key_path:
        server_public_key = parse_server_pubkey(server_key_path)
        client_public, client_secret = zmq.curve_keypair()
        sub.setsockopt(zmq.CURVE_SERVERKEY, server_public_key)
        sub.setsockopt(zmq.CURVE_PUBLICKEY, client_public)
        sub.setsockopt(zmq.CURVE_SECRETKEY, client_secret)

    for ep in endpoints:
        if bind_mode:
            sub.bind(ep)
            print(f"  Listening on {ep} (bind mode)", file=sys.stderr)
        else:
            sub.connect(ep)
            print(f"  Connected to {ep}", file=sys.stderr)

    while running:
        try:
            frames = sub.recv_multipart()
        except zmq.Again:
            continue
        except zmq.ZMQError:
            break

        gps_info = None
        if len(frames) >= 2 and len(frames[0]) == ZMQ_GPS_FRAME.size:
            lat, lon, alt = ZMQ_GPS_FRAME.unpack(frames[0])
            gps_info = (lat, lon, alt)
            pcap_data = frames[1]
        else:
            pcap_data = frames[-1]

        # Write PCAP if requested
        if pcap_file:
            if use_gps:
                ts_sec, ts_usec, incl_len, orig_len = PCAP_REC_HDR.unpack_from(pcap_data, 0)
                payload = pcap_data[PCAP_REC_HDR.size:]
                if gps_info:
                    ppi_hdr = build_ppi_gps_header(*gps_info)
                else:
                    ppi_hdr = build_ppi_passthrough_header()
                new_len = len(ppi_hdr) + len(payload)
                pcap_file.write(PCAP_REC_HDR.pack(ts_sec, ts_usec, new_len, new_len))
                pcap_file.write(ppi_hdr)
                pcap_file.write(payload)
                pcap_file.flush()
            else:
                pcap_file.write(pcap_data)
                pcap_file.flush()

        pkt = parse_ble_packet(pcap_data)
        if pkt:
            state.add_packet(pkt, gps_info)

    sub.close()
    ctx.term()


def parse_server_pubkey(path):
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.startswith("server_public_key="):
                return line.split("=", 1)[1].encode()
            if line.startswith("public_key="):
                return line.split("=", 1)[1].encode()
    raise ValueError(f"No public key found in {path}")


# ---------------------------------------------------------------------------
# Dashboard HTML (self-contained, no external deps except Leaflet CDN for map)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ICE9 Bluetooth Sniffer</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font: 12px/1.4 monospace; background: #1a1a1a; color: #ccc; }

.toolbar { padding: 4px 8px; background: #252525; border-bottom: 1px solid #333;
           display: flex; align-items: center; gap: 12px; font-size: 11px; }
.toolbar b { color: #fff; }
.status { color: #888; }
.status.ok { color: #7c4; }
.spacer { flex: 1; }
button { font: 11px monospace; background: #333; color: #ccc; border: 1px solid #555;
         padding: 2px 8px; cursor: pointer; }
button:hover { background: #444; }
button.on { background: #653; border-color: #a75; color: #fa8; }

.tabs { display: flex; gap: 0; }
.tab { padding: 2px 10px; border: 1px solid #555; border-bottom: none; cursor: pointer;
       background: #252525; color: #888; margin-right: -1px; }
.tab.active { background: #1a1a1a; color: #ccc; border-bottom: 1px solid #1a1a1a;
              position: relative; z-index: 1; }
.tab:hover:not(.active) { color: #aaa; }

.stats { padding: 3px 8px; background: #202020; border-bottom: 1px solid #333;
         font-size: 11px; color: #888; display: flex; flex-wrap: wrap; gap: 0; }
.stats span { margin-right: 16px; }
.stats .val { color: #ccc; }

.panel { display: none; }
.panel.active { display: flex; flex-direction: column; height: calc(100vh - 52px); }

.table-area { flex: 1; overflow: auto; }

table { width: 100%; border-collapse: collapse; }
thead { position: sticky; top: 0; z-index: 2; }
th { background: #252525; border-bottom: 1px solid #444; padding: 4px 8px;
     text-align: left; color: #888; font-weight: normal; cursor: pointer; }
th:hover { color: #ccc; }
th.sorted::after { content: ' \25bc'; }
th.sorted.asc::after { content: ' \25b2'; }
td { padding: 3px 8px; border-bottom: 1px solid #2a2a2a; white-space: nowrap; }
tr:hover td { background: #222; }
tr.fresh td { background: #1a2a1a; }

.dim { color: #666; }
.grn { color: #7c4; }
.red { color: #c44; }
.blu { color: #68f; }
.org { color: #ca6; }
.yel { color: #ec5; }
.masked { color: #666; }

#map { flex: 1; width: 100%; }
.empty { padding: 40px; text-align: center; color: #555; }
.count { text-align: right; }
</style>
</head>
<body>

<div class="toolbar">
  <b>ice9-bluetooth</b>
  <span class="status" id="conn">disconnected</span>
  <div class="tabs" id="tabBar">
    <div class="tab active" data-tab="devices" onclick="switchTab('devices')">devices</div>
  </div>
  <span class="spacer"></span>
  <button id="privBtn" class="on" onclick="togglePrivacy()">MAC hidden</button>
</div>

<div class="stats">
  <span>pkts: <span class="val" id="sTotal">0</span></span>
  <span>rate: <span class="val" id="sRate">0</span>/s</span>
  <span>crc: <span class="val" id="sCrc">--</span></span>
  <span>devices: <span class="val" id="sMacs">0</span></span>
  <span>data: <span class="val" id="sData">0</span></span>
  <span>up: <span class="val" id="sUp">0s</span></span>
</div>

<div class="panel active" id="panelDevices">
  <div class="table-area" id="tWrap">
    <table>
      <thead><tr>
        <th data-col="last" class="sorted">last seen</th>
        <th data-col="mac">mac</th>
        <th data-col="type">type</th>
        <th data-col="rssi">rssi</th>
        <th data-col="freq">freq</th>
        <th data-col="pkts" class="count">pkts</th>
        <th data-col="crc">crc %</th>
        <th data-col="first">first seen</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
    <div class="empty" id="empty">waiting for devices...</div>
  </div>
</div>

<div class="panel" id="panelMap">
  <div id="map"></div>
</div>

<script>
let priv = true, map = null, marker = null, trail = [], curTab = 'devices';
let sortCol = 'last', sortAsc = false;
const GPS = __GPS_ENABLED__;
const tb = document.getElementById('tb');
let devices = [];

function switchTab(name) {
  curTab = name;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel'+name.charAt(0).toUpperCase()+name.slice(1)).classList.add('active');
  if (name === 'map' && map) map.invalidateSize();
}

function togglePrivacy() {
  priv = !priv;
  const b = document.getElementById('privBtn');
  b.textContent = priv ? 'MAC hidden' : 'MAC visible';
  b.classList.toggle('on', priv);
  renderDevices();
}

function mask(m) { return m ? 'xx:xx:xx:xx:xx:xx' : ''; }

function fmtT(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('en-US',{hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0');
}

function fmtUp(s) {
  if (s < 60) return Math.round(s)+'s';
  if (s < 3600) return Math.floor(s/60)+'m'+Math.round(s%60)+'s';
  return Math.floor(s/3600)+'h'+Math.floor((s%3600)/60)+'m';
}

function ago(ts) {
  const s = (Date.now()/1000) - ts;
  if (s < 2) return 'now';
  if (s < 60) return Math.round(s)+'s ago';
  if (s < 3600) return Math.floor(s/60)+'m ago';
  return Math.floor(s/3600)+'h ago';
}

/* Column sorting */
document.querySelectorAll('th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (sortCol === col) { sortAsc = !sortAsc; }
    else { sortCol = col; sortAsc = false; }
    document.querySelectorAll('th').forEach(h => { h.classList.remove('sorted','asc'); });
    th.classList.add('sorted');
    if (sortAsc) th.classList.add('asc');
    renderDevices();
  });
});

function sortDevices(devs) {
  const dir = sortAsc ? 1 : -1;
  return devs.slice().sort((a, b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (typeof va === 'string') return dir * va.localeCompare(vb);
    return dir * ((va||0) - (vb||0));
  });
}

function renderDevices() {
  const now = Date.now() / 1000;
  const sorted = sortDevices(devices);
  document.getElementById('empty').style.display = sorted.length ? 'none' : 'block';

  /* Rebuild table body */
  const frag = document.createDocumentFragment();
  for (const d of sorted) {
    const tr = document.createElement('tr');
    const fresh = (now - d.last) < 3;
    if (fresh) tr.className = 'fresh';
    const mc = priv ? mask(d.mac) : d.mac;
    const total = d.crc_ok + d.crc_bad;
    const crcPct = total > 0 ? Math.round(100*d.crc_ok/total)+'%' : '-';
    const crcCls = total > 0 ? (d.crc_ok/total > 0.8 ? 'grn' : d.crc_ok/total > 0.4 ? 'yel' : 'red') : 'dim';
    const isAdv = d.type !== 'DATA';
    tr.innerHTML =
      `<td class="dim">${ago(d.last)}</td>`+
      `<td class="${priv?'masked':''}">${mc}</td>`+
      `<td class="${isAdv?'blu':'org'}">${d.type}</td>`+
      `<td>${d.rssi}</td>`+
      `<td>${d.freq}</td>`+
      `<td class="count">${d.pkts.toLocaleString()}</td>`+
      `<td class="${crcCls}">${crcPct}</td>`+
      `<td class="dim">${fmtT(d.first)}</td>`;
    frag.appendChild(tr);
  }
  tb.innerHTML = '';
  tb.appendChild(frag);
}

function updStats(s) {
  document.getElementById('sTotal').textContent = s.total.toLocaleString();
  document.getElementById('sRate').textContent = s.rate;
  document.getElementById('sCrc').textContent = s.crc_pct!==null ? s.crc_pct+'%' : '--';
  document.getElementById('sMacs').textContent = s.macs;
  document.getElementById('sData').textContent = s.data_pkts.toLocaleString();
  document.getElementById('sUp').textContent = fmtUp(s.uptime);
  if (GPS && s.last_gps && map) {
    const ll = s.last_gps;
    if (!marker) {
      marker = L.circleMarker(ll,{radius:6,color:'#68f',fillColor:'#68f',fillOpacity:0.8,weight:1}).addTo(map);
      map.setView(ll,15);
    } else {
      marker.setLatLng(ll);
    }
    trail.push(ll);
    if (trail.length>500) trail=trail.slice(-500);
    if (window._t) map.removeLayer(window._t);
    if (trail.length>1) window._t=L.polyline(trail,{color:'#68f',weight:2,opacity:0.5}).addTo(map);
  }
}

if (GPS) {
  const tab = document.createElement('div');
  tab.className = 'tab';
  tab.dataset.tab = 'map';
  tab.textContent = 'map';
  tab.onclick = function(){ switchTab('map'); };
  document.getElementById('tabBar').appendChild(tab);
  const lk=document.createElement('link'); lk.rel='stylesheet';
  lk.href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'; document.head.appendChild(lk);
  const sc=document.createElement('script');
  sc.src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
  sc.onload=function(){
    map=L.map('map',{zoomControl:true}).setView([0,0],2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'OSM'}).addTo(map);
  }; document.body.appendChild(sc);
}

const es = new EventSource('/events');
const cn = document.getElementById('conn');
es.onopen = ()=>{ cn.textContent='connected'; cn.className='status ok'; };
es.onerror = ()=>{ cn.textContent='disconnected'; cn.className='status'; };
es.addEventListener('update', e => {
  const d = JSON.parse(e.data);
  devices = d.devices;
  updStats(d.stats);
  renderDevices();
});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global running, gps_enabled

    parser = argparse.ArgumentParser(
        description="Live web dashboard for ice9-bluetooth-sniffer")
    parser.add_argument("endpoints", nargs="+",
                        help="ZMQ endpoints (e.g. tcp://localhost:5555)")
    parser.add_argument("-p", "--port", type=int, default=8099,
                        help="HTTP port for dashboard (default: 8099)")
    parser.add_argument("-w", "--write", metavar="FILE",
                        help="Also write received packets to PCAP file")
    parser.add_argument("--gps", action="store_true",
                        help="Enable GPS column and map display")
    parser.add_argument("--server-key", metavar="FILE",
                        help="Server public key file for CURVE encryption")
    parser.add_argument("--bind", action="store_true",
                        help="Bind SUB socket (sensors connect to us) instead of connecting")
    args = parser.parse_args()

    gps_enabled = args.gps

    def sig_handler(sig, frame):
        global running
        running = False
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    pcap_file = None
    if args.write:
        pcap_file = open(args.write, "wb")
        dlt = DLT_PPI if args.gps else DLT_BLUETOOTH_LE_LL_WITH_PHDR
        snaplen = 4 + 2 + 255 + 3
        if args.gps:
            snaplen += PPI_GPS_SIZE
        pcap_file.write(PCAP_GLOBAL_HDR.pack(0xA1B2C3D4, 2, 4, 0, 0, snaplen, dlt))
        pcap_file.flush()

    # Start ZMQ receiver thread
    zmq_thread = threading.Thread(
        target=zmq_receiver,
        args=(args.endpoints, args.server_key, pcap_file, args.gps, args.bind),
        daemon=True,
    )
    zmq_thread.start()

    # Start HTTP server
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), DashboardHandler)
    httpd.timeout = 1

    print(f"\n  ICE9 Bluetooth Sniffer - Web Dashboard", file=sys.stderr)
    print(f"  {'='*40}", file=sys.stderr)
    print(f"  Dashboard:  http://localhost:{args.port}", file=sys.stderr)
    if args.write:
        dlt_name = "DLT 192 (PPI+GPS)" if args.gps else "DLT 256 (BLE)"
        print(f"  PCAP file:  {args.write} ({dlt_name})", file=sys.stderr)
    print(f"  Privacy:    MAC addresses hidden by default", file=sys.stderr)
    print(f"  {'='*40}\n", file=sys.stderr)

    try:
        while running:
            httpd.handle_request()
    except (KeyboardInterrupt, SystemExit):
        pass

    running = False
    print("\nShutting down...", file=sys.stderr)
    zmq_thread.join(timeout=3)
    httpd.server_close()

    if pcap_file:
        pcap_file.close()
        print(f"PCAP written to {args.write}", file=sys.stderr)

    print("Dashboard stopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
