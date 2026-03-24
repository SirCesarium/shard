#!/usr/bin/env python3
"""
Shard Security Tool: Malformed Packet Attack PoC (Fuzzing)
This script sends invalid packets to the server to test its robustness:
1. Invalid protocol version (0x99)
2. Payload length field larger than actual data
3. Packet smaller than the minimum header size (34 bytes)

Usage: sudo python3 tools/malformed_packet.py --port 3000
"""

from scapy.all import *
import argparse

def run_fuzz_test(port):
    target_ip = "127.0.0.1"
    print(f"[*] Starting Malformed Packet Test on {target_ip}:{port}")

    # Test 1: Wrong Protocol Version (0x99)
    print("[*] Sending: Wrong version (0x99)")
    payload_v99 = bytearray([0x99] + [0]*49) # Wrong version, then 49 bytes of zeros
    send(IP(dst=target_ip)/UDP(dport=port)/Raw(load=payload_v99), verbose=False)

    # Test 2: Mismatched payload length (says 500, sends 1)
    print("[*] Sending: Mismatched payload length")
    payload_mismatch = bytearray([0x01, 0x00] + [0x00]*28 + [0x01, 0xf4] + [0x41]*10) # 0x01F4 = 500
    send(IP(dst=target_ip)/UDP(dport=port)/Raw(load=payload_mismatch), verbose=False)

    # Test 3: Extremely short packet (10 bytes)
    print("[*] Sending: Too short for header (10 bytes)")
    payload_short = bytearray([0x01]*10)
    send(IP(dst=target_ip)/UDP(dport=port)/Raw(load=payload_short), verbose=False)

    print("\n[+] All tests sent. Check the server logs (should not crash!).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shard Malformed Packet Attack PoC")
    parser.add_argument("--port", type=int, default=3000, help="UDP port (default: 3000)")
    args = parser.parse_args()
    run_fuzz_test(args.port)
