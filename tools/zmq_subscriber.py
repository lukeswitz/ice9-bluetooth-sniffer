#!/usr/bin/env python3
# Copyright 2025-2026 CEMAXECUTER LLC
"""
ZMQ subscriber test harness for ice9-bluetooth-sniffer.

Connects to the ZMQ PUB socket and receives BLE packets as PCAP records.
Can display live packet info, write to a PCAP file, or both.

Usage:
    # Display live packets from a local sensor:
    python3 zmq_subscriber.py tcp://localhost:5555

    # Write to PCAP file:
    python3 zmq_subscriber.py tcp://localhost:5555 -w output.pcap

    # Subscribe to multiple sensors:
    python3 zmq_subscriber.py tcp://sensor1:5555 tcp://sensor2:5555

    # Quiet mode (only write PCAP, no terminal output):
    python3 zmq_subscriber.py tcp://localhost:5555 -w output.pcap -q

    # Encrypted connection (CURVE):
    python3 zmq_subscriber.py tcp://sensor1:5555 --server-key server.key.pub

Requirements:
    pip install pyzmq
"""

import argparse
import signal
import struct
import sys
import time

try:
    import zmq
except ImportError:
    print("pyzmq is required: pip install pyzmq", file=sys.stderr)
    sys.exit(1)

# PCAP structures (matching pcap.c)
PCAP_GLOBAL_HDR = struct.Struct("<IHHiIII")
PCAP_REC_HDR = struct.Struct("<IIII")      # ts_sec, ts_usec, incl_len, orig_len
BLE_RF_HDR = struct.Struct("<bbbBIH")      # rf_channel, signal_power, noise_power,
                                            # aa_offenses, ref_aa, flags

# BLE RF Info flags
LE_DEWHITENED         = 0x0001
LE_SIGNAL_POWER_VALID = 0x0002
LE_NOISE_POWER_VALID  = 0x0004
LE_CRC_CHECKED        = 0x0400
LE_CRC_VALID          = 0x0800

# BLE advertising channel access address
BLE_ADV_AA = 0x8E89BED6

DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256

running = True


def signal_handler(sig, frame):
    global running
    running = False


def channel_to_freq(ch):
    """Convert BLE RF channel number to frequency in MHz."""
    return 2402 + ch * 2


def parse_ble_packet(data):
    """Parse a ZMQ message containing a PCAP record."""
    if len(data) < PCAP_REC_HDR.size + BLE_RF_HDR.size:
        return None

    # Parse PCAP record header
    ts_sec, ts_usec, incl_len, orig_len = PCAP_REC_HDR.unpack_from(data, 0)
    offset = PCAP_REC_HDR.size

    # Parse BLE RF Info header
    rf_channel, signal_power, noise_power, aa_offenses, ref_aa, flags = \
        BLE_RF_HDR.unpack_from(data, offset)
    offset += BLE_RF_HDR.size

    # Remaining bytes are the BLE packet (AA + PDU + CRC)
    ble_data = data[offset:]

    # Extract access address (first 4 bytes, little-endian)
    aa = struct.unpack_from("<I", ble_data, 0)[0] if len(ble_data) >= 4 else 0

    crc_checked = bool(flags & LE_CRC_CHECKED)
    crc_valid = bool(flags & LE_CRC_VALID) if crc_checked else None

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
        "data_len": len(ble_data),
        "ble_data": ble_data,
    }


def write_pcap_header(f):
    """Write PCAP global header."""
    f.write(PCAP_GLOBAL_HDR.pack(
        0xA1B2C3D4,  # magic
        2, 4,         # version
        0,            # timezone
        0,            # sigfigs
        4 + 2 + 255 + 3,  # snaplen
        DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    ))
    f.flush()


def parse_server_pubkey(path):
    """Read server public key from a .pub key file."""
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


def main():
    parser = argparse.ArgumentParser(
        description="ZMQ subscriber for ice9-bluetooth-sniffer")
    parser.add_argument("endpoints", nargs="+",
                        help="ZMQ endpoints (e.g. tcp://localhost:5555)")
    parser.add_argument("-w", "--write", metavar="FILE",
                        help="Write received packets to PCAP file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="Exit after N seconds (0 = run forever)")
    parser.add_argument("--server-key", metavar="FILE",
                        help="Server public key file for CURVE encryption")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.setsockopt(zmq.SUBSCRIBE, b"")  # subscribe to all messages
    sub.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout for clean shutdown

    if args.server_key:
        server_public_key = parse_server_pubkey(args.server_key)
        client_public, client_secret = zmq.curve_keypair()
        sub.setsockopt(zmq.CURVE_SERVERKEY, server_public_key)
        sub.setsockopt(zmq.CURVE_PUBLICKEY, client_public)
        sub.setsockopt(zmq.CURVE_SECRETKEY, client_secret)
        if not args.quiet:
            print(f"CURVE encryption enabled", file=sys.stderr)

    for endpoint in args.endpoints:
        sub.connect(endpoint)
        if not args.quiet:
            print(f"Connected to {endpoint}", file=sys.stderr)

    pcap_file = None
    if args.write:
        pcap_file = open(args.write, "wb")
        write_pcap_header(pcap_file)
        if not args.quiet:
            print(f"Writing PCAP to {args.write}", file=sys.stderr)

    pkt_count = 0
    crc_valid_count = 0
    crc_invalid_count = 0
    start_time = time.time()

    if not args.quiet:
        print(f"{'Time':>10s}  {'Freq':>4s}  {'RSSI':>5s}  {'AA':>10s}  "
              f"{'Len':>4s}  {'CRC':>5s}", file=sys.stderr)
        print("-" * 50, file=sys.stderr)

    while running:
        if args.timeout and (time.time() - start_time) > args.timeout:
            break

        try:
            data = sub.recv()
        except zmq.Again:
            continue

        # Write raw PCAP record to file (the message IS the pcap record)
        if pcap_file:
            pcap_file.write(data)
            pcap_file.flush()

        pkt = parse_ble_packet(data)
        if pkt is None:
            continue

        pkt_count += 1
        if pkt["crc_checked"]:
            if pkt["crc_valid"]:
                crc_valid_count += 1
            else:
                crc_invalid_count += 1

        if not args.quiet:
            elapsed = time.time() - start_time
            crc_str = "  -  "
            if pkt["crc_checked"]:
                crc_str = " OK  " if pkt["crc_valid"] else " BAD "
            is_adv = " ADV" if pkt["aa"] == BLE_ADV_AA else "DATA"
            print(f"{elapsed:10.3f}  {pkt['freq_mhz']:4d}  "
                  f"{pkt['signal_power']:5d}  "
                  f"{pkt['aa']:08x}{is_adv}  "
                  f"{pkt['data_len']:4d}  {crc_str}")

    # Summary
    elapsed = time.time() - start_time
    if not args.quiet:
        print(f"\n--- {pkt_count} packets in {elapsed:.1f}s "
              f"({pkt_count/max(elapsed,0.001):.1f} pkt/s) ---",
              file=sys.stderr)
        if crc_valid_count + crc_invalid_count > 0:
            total = crc_valid_count + crc_invalid_count
            pct = 100.0 * crc_valid_count / total
            print(f"CRC: {crc_valid_count} valid, {crc_invalid_count} invalid "
                  f"({pct:.1f}% valid)", file=sys.stderr)

    if pcap_file:
        pcap_file.close()
        if not args.quiet:
            print(f"PCAP written to {args.write}", file=sys.stderr)

    sub.close()
    ctx.term()


if __name__ == "__main__":
    main()
