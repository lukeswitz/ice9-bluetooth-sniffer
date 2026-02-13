#!/usr/bin/env python3
# Copyright 2025-2026 CEMAXECUTER LLC
"""
Live web dashboard for ice9-bluetooth-sniffer ZMQ streams.

Connects to one or more ZMQ PUB endpoints and presents a Kismet-style device
list with BLE device fingerprinting, CRC-gated tracking, and aggregate
summaries. Features a privacy toggle to mask MAC addresses (useful for video
recording / streaming).

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

    # Update Bluetooth device database (Nordic Semiconductor, MIT licensed):
    python3 zmq_web_dashboard.py tcp://localhost:5555 --update-bt-db

Requirements:
    pip install pyzmq
"""

import argparse
import json
import os
import queue
import signal
import struct
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError

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


# ---------------------------------------------------------------------------
# BLE device fingerprinting
# ---------------------------------------------------------------------------
BLE_COMPANY_IDS = {
    0x0001: "Nokia",
    0x0002: "Intel",
    0x0006: "Microsoft",
    0x000A: "Qualcomm",
    0x000D: "Texas Instruments",
    0x000F: "Broadcom",
    0x004C: "Apple",
    0x004F: "Meta (Oculus)",
    0x0059: "Nordic",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x009E: "Bose",
    0x00D2: "Bose",
    0x00E0: "Google",
    0x012D: "Sony",
    0x0131: "Huawei",
    0x0157: "Anhui Huami (Amazfit)",
    0x0171: "Amazon",
    0x01DA: "Fitbit",
    0x0310: "Tile",
    0x038F: "Xiaomi",
    0x0822: "Shenzhen Goodix",
}

APPLE_CONTINUITY_TYPES = {
    0x01: "Setup",
    0x02: "iBeacon",
    0x05: "AirDrop",
    0x07: "AirPods",
    0x09: "AirPlay",
    0x0C: "Handoff",
    0x0D: "Hotspot",
    0x0E: "Hotspot Src",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",
    0x12: "Find My",
}

AD_TYPE_FLAGS            = 0x01
AD_TYPE_UUID16_INCOMPLETE = 0x02
AD_TYPE_UUID16_COMPLETE  = 0x03
AD_TYPE_NAME_SHORT       = 0x08
AD_TYPE_NAME_COMPLETE    = 0x09
AD_TYPE_TX_POWER         = 0x0A
AD_TYPE_SVC_DATA_16      = 0x16  # Service Data - 16-bit UUID (very common)
AD_TYPE_APPEARANCE       = 0x19
AD_TYPE_MANUFACTURER     = 0xFF

BLE_APPEARANCE = {
    0x0000: "Unknown",
    0x0040: "Phone",
    0x0080: "Computer",
    0x00C0: "Watch",
    0x00C1: "Sports Watch",
    0x0100: "Clock",
    0x0140: "Display",
    0x0180: "Remote",
    0x01C0: "Eyeglasses",
    0x0200: "Tag",
    0x0240: "Keyring",
    0x0300: "Pulse Oximeter",
    0x03C0: "Heart Rate Sensor",
    0x0440: "Blood Pressure",
    0x04C0: "HID",
    0x04C1: "Keyboard",
    0x04C2: "Mouse",
    0x04C3: "Joystick",
    0x04C4: "Gamepad",
    0x0540: "Barcode Scanner",
    0x0580: "Thermometer",
    0x0940: "Hearing Aid",
    0x0CC0: "Sensor",
    0x0CC1: "Motion Sensor",
}

BLE_UUID16_SERVICES = {
    # Standard GATT services
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Current Time",
    0x1806: "Ref Time Update",
    0x1807: "Next DST Change",
    0x1808: "Glucose",
    0x1809: "Health Thermo",
    0x180A: "Device Info",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert",
    0x180F: "Battery",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notify",
    0x1812: "HID",
    0x1813: "Scan Params",
    0x1814: "Running Speed",
    0x1816: "Cycling Speed",
    0x1818: "Cycling Power",
    0x1819: "Location Nav",
    0x181A: "Environmental",
    0x181B: "Body Composition",
    0x181C: "User Data",
    0x181D: "Weight Scale",
    0x181E: "Bond Mgmt",
    0x1820: "IP Support",
    0x1821: "Indoor Positioning",
    0x1822: "Pulse Oximeter",
    0x1824: "Transport Discovery",
    0x1825: "Object Transfer",
    0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning",
    0x1828: "Mesh Proxy",
    0x1829: "Reconnect Config",
    0x183A: "Audio Input",
    0x183B: "Volume Control",
    0x183C: "Volume Offset",
    0x183E: "Coord Set ID",
    0x184D: "Microphone",
    0x184E: "Audio Stream",
    0x1853: "Common Audio",
    0x1854: "Hearing Access",
    0x1855: "Telephony",
    0x1856: "Media Control",
    0x1857: "Generic Media",
    0x1858: "Constant Tone",
    0x1859: "Object ID",
    # Member company 16-bit UUIDs (0xFCxx, 0xFDxx, 0xFExx range)
    0xFCB2: "Apple",
    0xFD62: "Fitbit",
    0xFD6F: "Exposure Notify",
    0xFD69: "Samsung",
    0xFD82: "Loop (Disney)",
    0xFDA6: "OPPO",
    0xFDB5: "OnePlus",
    0xFDCF: "Nreal",
    0xFDDF: "Harman (JBL)",
    0xFDF0: "Google Nearby",
    0xFE03: "Amazon",
    0xFE07: "Sonos",
    0xFE0D: "Xiaomi",
    0xFE0F: "Philips",
    0xFE13: "Apple ANCS",
    0xFE26: "Google",
    0xFE2C: "Google Fast Pair",
    0xFE43: "Andreas Stihl",
    0xFE50: "Google",
    0xFE59: "Nordic DFU",
    0xFE6E: "JBL",
    0xFE78: "Garmin",
    0xFE8A: "Apple MFi",
    0xFE95: "Xiaomi Mi",
    0xFE9F: "Google",
    0xFEA0: "Google",
    0xFEAA: "Eddystone",
    0xFEAD: "Tile",
    0xFEB2: "Microsoft",
    0xFEB8: "Facebook",
    0xFEBB: "Adafruit",
    0xFEBE: "Bose",
    0xFEC7: "Apple Notification",
    0xFEC8: "Apple MIDI",
    0xFEC9: "Apple ANCS",
    0xFED4: "Apple",
    0xFED8: "Google Thread",
    0xFEDF: "Design SHIFT",
    0xFEE7: "Tencent",
    0xFEED: "Tile",
    0xFEF3: "Google",
    0xFEF5: "Dialog Semi",
}

AD_TYPE_UUID16_LIST = {0x02, 0x03}  # 16-bit UUID lists only (0x04-05 = 32-bit, 0x06-07 = 128-bit)

# ---------------------------------------------------------------------------
# Auto-updatable Bluetooth numbers database
# ---------------------------------------------------------------------------
NORDIC_DB_BASE = "https://raw.githubusercontent.com/NordicSemiconductor/bluetooth-numbers-database/master/v1"
NORDIC_COMPANY_IDS_URL = f"{NORDIC_DB_BASE}/company_ids.json"
NORDIC_SERVICE_UUIDS_URL = f"{NORDIC_DB_BASE}/service_uuids.json"

# Cache directory: ~/.cache/ice9-bt-sniffer/
BT_DB_CACHE_DIR = Path.home() / ".cache" / "ice9-bt-sniffer"


def bt_db_update(quiet=False):
    """Download latest Bluetooth numbers from Nordic Semiconductor database."""
    BT_DB_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    files = [
        (NORDIC_COMPANY_IDS_URL, BT_DB_CACHE_DIR / "company_ids.json"),
        (NORDIC_SERVICE_UUIDS_URL, BT_DB_CACHE_DIR / "service_uuids.json"),
    ]

    for url, path in files:
        try:
            if not quiet:
                print(f"  Downloading {url} ...", file=sys.stderr)
            with urlopen(url, timeout=15) as resp:
                data = resp.read()
            # Validate JSON before writing
            json.loads(data)
            path.write_bytes(data)
            if not quiet:
                print(f"  Saved to {path}", file=sys.stderr)
        except (URLError, OSError, json.JSONDecodeError) as e:
            print(f"  WARNING: Failed to download {url}: {e}", file=sys.stderr)
            return False

    if not quiet:
        print(f"  Bluetooth numbers database updated.", file=sys.stderr)
    return True


def bt_db_load():
    """Load cached Nordic database and merge over hardcoded dicts.

    Hardcoded entries take priority (they include curated short names),
    but any codes NOT in the hardcoded dicts get filled in from the
    Nordic database.
    """
    # Company IDs
    cid_path = BT_DB_CACHE_DIR / "company_ids.json"
    if cid_path.exists():
        try:
            entries = json.loads(cid_path.read_text())
            added = 0
            for entry in entries:
                code = entry.get("code")
                name = entry.get("name", "")
                if code is not None and code not in BLE_COMPANY_IDS and name:
                    BLE_COMPANY_IDS[code] = name
                    added += 1
            print(f"  BT DB: loaded {added} additional company IDs from cache", file=sys.stderr)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARNING: Failed to load {cid_path}: {e}", file=sys.stderr)

    # Service UUIDs
    svc_path = BT_DB_CACHE_DIR / "service_uuids.json"
    if svc_path.exists():
        try:
            entries = json.loads(svc_path.read_text())
            added = 0
            for entry in entries:
                uuid_str = entry.get("uuid", "")
                name = entry.get("name", "")
                try:
                    uuid_int = int(uuid_str, 16)
                except (ValueError, TypeError):
                    continue
                if uuid_int not in BLE_UUID16_SERVICES and name:
                    BLE_UUID16_SERVICES[uuid_int] = name
                    added += 1
            print(f"  BT DB: loaded {added} additional service UUIDs from cache", file=sys.stderr)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARNING: Failed to load {svc_path}: {e}", file=sys.stderr)


def classify_mac_type(ble_data):
    """Classify MAC address type from PDU header TxAdd bit."""
    if len(ble_data) < 6:
        return "unknown"
    # TxAdd is bit 6 of the first header byte (ble_data[4])
    tx_add = (ble_data[4] >> 6) & 1
    if tx_add == 0:
        return "public"
    # Random address: check the two MSBs of the address (ble_data[11])
    if len(ble_data) < 12:
        return "random"
    msb = ble_data[11]
    top2 = (msb >> 6) & 0x03
    if top2 == 0x03:
        return "static"       # static random -- persists per boot
    elif top2 == 0x01:
        return "resolvable"   # resolvable private -- rotates, can be resolved with IRK
    elif top2 == 0x00:
        return "non-resolv"   # non-resolvable private -- fully anonymous
    return "random"


def parse_ad_structures(adv_data):
    """Parse AD structures from BLE advertising data payload."""
    result = {
        "name": None,
        "manufacturer": None,
        "company_id": None,
        "tx_power": None,
        "appearance": None,
        "apple_type": None,
        "mfr_data": None,
        "services": [],
    }
    i = 0
    while i < len(adv_data):
        if i + 1 >= len(adv_data):
            break
        length = adv_data[i]
        if length == 0 or i + length >= len(adv_data):
            break
        ad_type = adv_data[i + 1]
        ad_data = adv_data[i + 2 : i + 1 + length]

        if ad_type in (AD_TYPE_NAME_COMPLETE, AD_TYPE_NAME_SHORT):
            try:
                result["name"] = ad_data.decode("utf-8", errors="replace")
            except Exception:
                pass

        elif ad_type == AD_TYPE_TX_POWER and len(ad_data) >= 1:
            result["tx_power"] = struct.unpack("b", ad_data[:1])[0]

        elif ad_type == AD_TYPE_APPEARANCE and len(ad_data) >= 2:
            code = struct.unpack("<H", ad_data[:2])[0]
            # Match by category (top bits) or exact
            result["appearance"] = BLE_APPEARANCE.get(
                code, BLE_APPEARANCE.get(code & 0xFFC0, f"0x{code:04x}"))

        elif ad_type in AD_TYPE_UUID16_LIST and len(ad_data) >= 2:
            # Parse 16-bit service UUIDs (complete or incomplete lists)
            for j in range(0, len(ad_data) - 1, 2):
                uuid16 = struct.unpack("<H", ad_data[j:j+2])[0]
                svc = BLE_UUID16_SERVICES.get(uuid16, f"0x{uuid16:04x}")
                if svc not in result["services"]:
                    result["services"].append(svc)

        elif ad_type == AD_TYPE_SVC_DATA_16 and len(ad_data) >= 2:
            # Service Data: first 2 bytes are the 16-bit UUID, rest is data
            uuid16 = struct.unpack("<H", ad_data[:2])[0]
            svc = BLE_UUID16_SERVICES.get(uuid16, f"0x{uuid16:04x}")
            if svc not in result["services"]:
                result["services"].append(svc)

        elif ad_type == AD_TYPE_MANUFACTURER and len(ad_data) >= 2:
            cid = struct.unpack("<H", ad_data[:2])[0]
            result["company_id"] = cid
            result["manufacturer"] = BLE_COMPANY_IDS.get(cid, f"0x{cid:04x}")
            result["mfr_data"] = ad_data[2:]

            # Apple Continuity protocol parsing
            if cid == 0x004C and len(ad_data) >= 3:
                apple_msg_type = ad_data[2]
                result["apple_type"] = APPLE_CONTINUITY_TYPES.get(
                    apple_msg_type, f"0x{apple_msg_type:02x}")

        i += 1 + length

    return result


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
    mac_type = None
    fingerprint = {}
    if is_adv and len(ble_data) >= 6:
        pdu_type = ble_data[4] & 0x0F
        pdu_names = {
            0: "ADV_IND", 1: "ADV_DIRECT", 2: "ADV_NONCONN",
            3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND",
            6: "ADV_SCAN_IND", 7: "ADV_EXT",
        }
        pdu_type_name = pdu_names.get(pdu_type, f"ADV_{pdu_type}")
        mac_type = classify_mac_type(ble_data)

        # Only PDU types 0 (ADV_IND), 2 (ADV_NONCONN), 4 (SCAN_RSP),
        # 6 (ADV_SCAN_IND) carry AD structures.
        # Types 1 (ADV_DIRECT), 3 (SCAN_REQ), 5 (CONNECT_IND) do NOT --
        # their payload is MAC addresses / connection params, not AD data.
        # Only parse CRC-valid packets to avoid false fingerprints from
        # bit errors (corrupted bytes decode as garbage AD structures).
        ad_pdu_types = {0, 2, 4, 6}
        crc_ok = (crc_valid is True) or (not crc_checked)
        if crc_ok and pdu_type in ad_pdu_types and len(ble_data) > 12:
            pdu_len = ble_data[5]
            adv_data_start = 12  # AA(4) + Header(2) + AdvA(6)
            adv_data_end = min(6 + pdu_len, len(ble_data))
            if adv_data_end > adv_data_start:
                fingerprint = parse_ad_structures(
                    ble_data[adv_data_start:adv_data_end])

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
        "mac_type": mac_type,
        "data_len": len(ble_data),
        "fingerprint": fingerprint,
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
        # Channel activity: rf_channel -> packet count
        self.channel_counts = {}
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

            # Track channel activity
            rf_ch = pkt.get("rf_channel")
            if rf_ch is not None:
                self.channel_counts[rf_ch] = self.channel_counts.get(rf_ch, 0) + 1

            mac = pkt["mac"]
            if not mac:
                self.data_packets += 1
                return

            # Only create/update device entries for CRC-valid packets.
            # CRC-failed packets have bit errors that corrupt MAC addresses,
            # PDU types, and AD data -- creating phantom device entries.
            # When CRC checking is off, allow all packets (backward compat).
            crc_ok = (pkt["crc_valid"] is True) or (not pkt["crc_checked"])
            if not crc_ok:
                return

            now = round(pkt["timestamp"], 6)
            fp = pkt.get("fingerprint", {})
            rssi = pkt["signal_power"]

            if mac in self.devices:
                d = self.devices[mac]
                d["pkts"] += 1
                d["last"] = now
                d["freq"] = pkt["freq_mhz"]
                d["type"] = pkt["pdu_type"]
                # RSSI tracking: best, min, sum, count
                if rssi > d["rssi"]:
                    d["rssi"] = rssi
                if rssi < d["rssi_min"]:
                    d["rssi_min"] = rssi
                d["rssi_sum"] += rssi
                d["rssi_cnt"] += 1
                if pkt["crc_valid"]:
                    d["crc_ok"] += 1
                elif pkt["crc_valid"] is False:
                    d["crc_bad"] += 1
                if gps_info:
                    d["lat"] = round(gps_info[0], 6)
                    d["lon"] = round(gps_info[1], 6)
                # Update fingerprint fields (keep best info seen)
                if fp.get("name") and not d.get("name"):
                    d["name"] = fp["name"]
                if fp.get("manufacturer") and not d.get("mfr"):
                    d["mfr"] = fp["manufacturer"]
                if fp.get("apple_type") and not d.get("apple"):
                    d["apple"] = fp["apple_type"]
                if fp.get("appearance") and not d.get("appear"):
                    d["appear"] = fp["appearance"]
                if fp.get("tx_power") is not None and d.get("tx_pwr") is None:
                    d["tx_pwr"] = fp["tx_power"]
                for svc in fp.get("services") or []:
                    if svc not in d["services"]:
                        d["services"].append(svc)
            else:
                d = {
                    "mac": mac,
                    "first": now,
                    "last": now,
                    "freq": pkt["freq_mhz"],
                    "rssi": rssi,
                    "rssi_min": rssi,
                    "rssi_sum": rssi,
                    "rssi_cnt": 1,
                    "type": pkt["pdu_type"],
                    "pkts": 1,
                    "crc_ok": 1 if pkt["crc_valid"] else 0,
                    "crc_bad": 1 if pkt["crc_valid"] is False else 0,
                    "mac_type": pkt.get("mac_type", ""),
                    "name": fp.get("name") or "",
                    "mfr": fp.get("manufacturer") or "",
                    "apple": fp.get("apple_type") or "",
                    "appear": fp.get("appearance") or "",
                    "tx_pwr": fp.get("tx_power"),
                    "services": list(fp.get("services") or []),
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
            devs = []
            for d in self.devices.values():
                # Add computed avg RSSI for the JSON output
                dd = dict(d)
                dd["rssi_avg"] = round(d["rssi_sum"] / d["rssi_cnt"]) if d["rssi_cnt"] else d["rssi"]
                # Don't send internal accumulators
                del dd["rssi_sum"]
                del dd["rssi_cnt"]
                devs.append(dd)
            devs.sort(key=lambda x: x["last"], reverse=True)
            return devs

    def get_summary(self):
        """Return aggregate breakdowns for the summary tab."""
        with self.lock:
            by_mfr = {}
            by_mac_type = {}
            by_pdu = {}
            by_svc = {}
            svc_device_count = 0
            top_talkers = []
            for d in self.devices.values():
                # Manufacturer
                m = d["mfr"] or "Unknown"
                by_mfr[m] = by_mfr.get(m, 0) + 1
                # MAC type
                mt = d["mac_type"] or "unknown"
                by_mac_type[mt] = by_mac_type.get(mt, 0) + 1
                # PDU type
                pt = d["type"]
                by_pdu[pt] = by_pdu.get(pt, 0) + 1
                # Services (count unique devices per service)
                svcs = d.get("services", [])
                if svcs:
                    svc_device_count += 1
                for svc in svcs:
                    by_svc[svc] = by_svc.get(svc, 0) + 1
                # Top talkers
                top_talkers.append((d["mac"], d["pkts"], d["mfr"], d["name"]))

            top_talkers.sort(key=lambda x: x[1], reverse=True)
            top10 = [{"mac": t[0], "pkts": t[1], "mfr": t[2], "name": t[3]}
                     for t in top_talkers[:15]]

            # Sort breakdowns by count descending
            def sorted_dict(d):
                return sorted(d.items(), key=lambda x: x[1], reverse=True)

            # Channel distribution: convert rf_channel to BLE channel number
            ch_dist = {}
            for rf_ch, cnt in self.channel_counts.items():
                freq = 2402 + rf_ch * 2
                if freq == 2402:
                    ble_ch = 37
                elif freq == 2426:
                    ble_ch = 38
                elif freq == 2480:
                    ble_ch = 39
                elif 2404 <= freq <= 2424:
                    ble_ch = (freq - 2404) // 2
                elif 2428 <= freq <= 2478:
                    ble_ch = (freq - 2428) // 2 + 11
                else:
                    ble_ch = rf_ch
                ch_dist[ble_ch] = ch_dist.get(ble_ch, 0) + cnt

            return {
                "by_mfr": sorted_dict(by_mfr),
                "by_mac_type": sorted_dict(by_mac_type),
                "by_pdu": sorted_dict(by_pdu),
                "by_svc": sorted_dict(by_svc),
                "svc_devices": svc_device_count,
                "total_devices": len(self.devices),
                "top_talkers": top10,
                "channels": sorted(ch_dist.items()),
            }

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
        elif path == "/api/summary":
            self._serve_json(state.get_summary())
        elif path == "/api/export.csv":
            self._serve_csv()
        elif path == "/api/export.json":
            self._serve_export_json()
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

    def _serve_csv(self):
        devs = state.get_devices()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", "attachment; filename=ble_devices.csv")
        self.end_headers()
        cols = ["mac", "mac_type", "mfr", "apple", "name", "appear", "services",
                "type", "rssi", "rssi_min", "rssi_avg", "tx_pwr", "pkts",
                "crc_ok", "crc_bad", "freq", "first", "last"]
        self.wfile.write((",".join(cols) + "\n").encode())
        for d in devs:
            row = []
            for c in cols:
                v = d.get(c, "")
                if c == "services":
                    v = "|".join(d.get("services", []))
                elif v is None:
                    v = ""
                row.append(str(v).replace(",", ";"))
            self.wfile.write((",".join(row) + "\n").encode())

    def _serve_export_json(self):
        data = {
            "stats": state.get_stats(),
            "summary": state.get_summary(),
            "devices": state.get_devices(),
        }
        payload = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", "attachment; filename=ble_capture.json")
        self.end_headers()
        self.wfile.write(payload)

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
                # Push full device list + stats + summary once per second
                devs = state.get_devices()
                stats = state.get_stats()
                summary = state.get_summary()
                payload = json.dumps({"stats": stats, "devices": devs, "summary": summary})
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

/* Summary panel */
.summary-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;
                padding: 12px; overflow: auto; flex: 1; }
.summary-card { background: #202020; border: 1px solid #333; padding: 8px; }
.summary-card h3 { color: #888; font-size: 11px; font-weight: normal;
                   text-transform: uppercase; margin-bottom: 6px; border-bottom: 1px solid #333;
                   padding-bottom: 4px; }
.summary-card.wide { grid-column: span 2; }
.summary-card.full { grid-column: span 3; }
.bar-row { display: flex; align-items: center; margin: 2px 0; font-size: 11px; }
.bar-label { width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { flex: 1; height: 12px; background: #2a2a2a; margin: 0 6px; position: relative; }
.bar-fill { height: 100%; position: absolute; left: 0; top: 0; }
.bar-val { width: 50px; text-align: right; color: #888; }
.talker-row { display: flex; font-size: 11px; margin: 1px 0; padding: 2px 0;
              border-bottom: 1px solid #2a2a2a; }
.talker-row .rank { width: 20px; color: #555; }
.talker-row .mac { width: 140px; }
.talker-row .info { flex: 1; color: #888; overflow: hidden; text-overflow: ellipsis; }
.talker-row .cnt { width: 60px; text-align: right; }
.ch-grid { display: flex; flex-wrap: wrap; gap: 2px; }
.ch-cell { width: 28px; height: 22px; display: flex; align-items: center; justify-content: center;
           font-size: 9px; border: 1px solid #333; }
.export-bar { padding: 4px 8px; background: #202020; border-top: 1px solid #333;
              display: flex; gap: 8px; align-items: center; font-size: 11px; }
@media (max-width: 900px) {
  .summary-grid { grid-template-columns: 1fr; }
  .summary-card.wide, .summary-card.full { grid-column: span 1; }
}
</style>
</head>
<body>

<div class="toolbar">
  <b>ice9-bluetooth</b>
  <span class="status" id="conn">disconnected</span>
  <div class="tabs" id="tabBar">
    <div class="tab active" data-tab="devices" onclick="switchTab('devices')">devices</div>
    <div class="tab" data-tab="summary" onclick="switchTab('summary')">summary</div>
  </div>
  <span class="spacer"></span>
  <button onclick="location.href='/api/export.csv'">export CSV</button>
  <button onclick="location.href='/api/export.json'">export JSON</button>
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
        <th data-col="mac_type">addr</th>
        <th data-col="mfr">manufacturer</th>
        <th data-col="name">name</th>
        <th data-col="services">services</th>
        <th data-col="type">type</th>
        <th data-col="rssi">rssi</th>
        <th data-col="pkts" class="count">pkts</th>
        <th data-col="crc">crc %</th>
        <th data-col="first">first seen</th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
    <div class="empty" id="empty">waiting for devices...</div>
  </div>
</div>

<div class="panel" id="panelSummary">
  <div class="summary-grid" id="summaryGrid">
    <div class="summary-card" id="cardMfr"><h3>by manufacturer</h3></div>
    <div class="summary-card" id="cardAddr"><h3>by address type</h3></div>
    <div class="summary-card" id="cardPdu"><h3>by PDU type</h3></div>
    <div class="summary-card" id="cardSvc"><h3>services seen (devices)</h3></div>
    <div class="summary-card wide" id="cardTop"><h3>top talkers (by packets)</h3></div>
    <div class="summary-card full" id="cardCh"><h3>channel activity</h3></div>
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
let devices = [], summary = null;

function switchTab(name) {
  curTab = name;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab===name));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel'+name.charAt(0).toUpperCase()+name.slice(1)).classList.add('active');
  if (name === 'map' && map) map.invalidateSize();
  if (name === 'summary' && summary) renderSummary(summary);
}

function togglePrivacy() {
  priv = !priv;
  const b = document.getElementById('privBtn');
  b.textContent = priv ? 'MAC hidden' : 'MAC visible';
  b.classList.toggle('on', priv);
  renderDevices();
  if (summary) renderSummary(summary);
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
    if (sortCol === 'services') { va = (a.services||[]).join(','); vb = (b.services||[]).join(','); }
    if (typeof va === 'string') return dir * va.localeCompare(vb);
    return dir * ((va||0) - (vb||0));
  });
}

function addrCls(t) {
  if (t==='public') return 'red';
  if (t==='static') return 'org';
  if (t==='resolvable') return 'yel';
  return 'dim';
}

function mfrLabel(d) {
  let s = d.mfr || '';
  if (d.apple) s = s ? s+' '+d.apple : d.apple;
  if (d.appear && d.appear !== 'Unknown') s = s ? s+' ('+d.appear+')' : d.appear;
  return s;
}

function rssiLabel(d) {
  if (d.rssi === d.rssi_min) return d.rssi;
  return d.rssi_min + '/' + d.rssi_avg + '/' + d.rssi;
}

function svcLabel(d) {
  const s = d.services || [];
  if (!s.length) return '';
  if (s.length <= 2) return s.join(', ');
  return s.slice(0,2).join(', ') + ' +' + (s.length-2);
}

function renderDevices() {
  const now = Date.now() / 1000;
  const sorted = sortDevices(devices);
  document.getElementById('empty').style.display = sorted.length ? 'none' : 'block';

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
    const mt = d.mac_type || '';
    tr.innerHTML =
      `<td class="dim">${ago(d.last)}</td>`+
      `<td class="${priv?'masked':''}">${mc}</td>`+
      `<td class="${addrCls(mt)}">${mt}</td>`+
      `<td>${mfrLabel(d)}</td>`+
      `<td class="blu">${d.name||''}</td>`+
      `<td class="dim">${svcLabel(d)}</td>`+
      `<td class="${isAdv?'blu':'org'}">${d.type}</td>`+
      `<td>${rssiLabel(d)}</td>`+
      `<td class="count">${d.pkts.toLocaleString()}</td>`+
      `<td class="${crcCls}">${crcPct}</td>`+
      `<td class="dim">${fmtT(d.first)}</td>`;
    frag.appendChild(tr);
  }
  tb.innerHTML = '';
  tb.appendChild(frag);
}

/* Summary tab rendering */
const barColors = {
  mfr: '#68f', addr: '#ca6', pdu: '#7c4', svc: '#c6f'
};

function renderBarChart(containerId, data, color, maxItems) {
  const el = document.getElementById(containerId);
  const h3 = el.querySelector('h3').outerHTML;
  if (!data || !data.length) { el.innerHTML = h3 + '<div class="dim" style="padding:8px">no data</div>'; return; }
  const max = data[0][1];
  const items = data.slice(0, maxItems || 12);
  let html = h3;
  for (const [label, count] of items) {
    const pct = max > 0 ? Math.round(100 * count / max) : 0;
    html += `<div class="bar-row"><span class="bar-label">${label}</span>`+
      `<span class="bar-track"><span class="bar-fill" style="width:${pct}%;background:${color};opacity:0.6"></span></span>`+
      `<span class="bar-val">${count.toLocaleString()}</span></div>`;
  }
  if (data.length > items.length) {
    html += `<div class="bar-row dim" style="justify-content:center">+${data.length-items.length} more</div>`;
  }
  el.innerHTML = html;
}

function renderTopTalkers(data) {
  const el = document.getElementById('cardTop');
  const h3 = el.querySelector('h3').outerHTML;
  if (!data || !data.length) { el.innerHTML = h3 + '<div class="dim" style="padding:8px">no data</div>'; return; }
  let html = h3;
  data.forEach((t, i) => {
    const mc = priv ? mask(t.mac) : t.mac;
    const info = [t.mfr, t.name].filter(Boolean).join(' - ') || '';
    html += `<div class="talker-row"><span class="rank">${i+1}</span>`+
      `<span class="mac ${priv?'masked':''}">${mc}</span>`+
      `<span class="info">${info}</span>`+
      `<span class="cnt">${t.pkts.toLocaleString()}</span></div>`;
  });
  el.innerHTML = html;
}

function renderChannels(data) {
  const el = document.getElementById('cardCh');
  const h3 = el.querySelector('h3').outerHTML;
  if (!data || !data.length) { el.innerHTML = h3 + '<div class="dim" style="padding:8px">no data</div>'; return; }
  const max = Math.max(...data.map(d => d[1]));
  let html = h3 + '<div class="ch-grid">';
  for (const [ch, cnt] of data) {
    const intensity = max > 0 ? cnt / max : 0;
    const r = Math.round(40 + intensity * 80);
    const g = Math.round(40 + intensity * 140);
    const b = Math.round(40 + intensity * 60);
    const isAdv = ch >= 37;
    const border = isAdv ? 'border-color:#ca6' : '';
    html += `<div class="ch-cell" style="background:rgb(${r},${g},${b});${border}" `+
      `title="Ch ${ch}: ${cnt.toLocaleString()} pkts">${ch}</div>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

function renderSummary(s) {
  renderBarChart('cardMfr', s.by_mfr, barColors.mfr, 12);
  renderBarChart('cardAddr', s.by_mac_type, barColors.addr, 8);
  renderBarChart('cardPdu', s.by_pdu, barColors.pdu, 8);
  renderBarChart('cardSvc', s.by_svc, barColors.svc, 12);
  /* Add context line showing how many devices have services at all */
  const svcEl = document.getElementById('cardSvc');
  if (s.total_devices > 0) {
    let ctx = svcEl.querySelector('.svc-ctx');
    if (!ctx) { ctx = document.createElement('div'); ctx.className = 'svc-ctx dim'; ctx.style.cssText = 'font-size:10px;padding:4px 0 0;border-top:1px solid #333;margin-top:4px'; svcEl.appendChild(ctx); }
    ctx.textContent = s.svc_devices + ' of ' + s.total_devices + ' devices advertise GATT services (most use mfr-specific data)';
  }
  renderTopTalkers(s.top_talkers);
  renderChannels(s.channels);
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
  summary = d.summary;
  updStats(d.stats);
  renderDevices();
  if (curTab === 'summary') renderSummary(summary);
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
    parser.add_argument("--update-bt-db", action="store_true",
                        help="Download/update Bluetooth numbers database from Nordic Semiconductor, then run")
    args = parser.parse_args()

    # Update Bluetooth numbers database if requested
    if args.update_bt_db:
        print("\n  Updating Bluetooth numbers database...", file=sys.stderr)
        bt_db_update()

    # Load cached Bluetooth numbers (merges over hardcoded fallbacks)
    bt_db_load()

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
