#!/usr/bin/env python3
"""
Shard Security Tool: Integrity Attack PoC (Bit-Flipping)
This script captures a valid Shard packet, flips a bit in the ciphertext, 
and resends it. The server should perform a 'Silent Drop' because 
the Auth Tag (Poly1305) will no longer be valid.

Usage: sudo python3 tools/integrity_attack.py --port 3000
"""

from scapy.all import *
import argparse

def run_integrity_test(port, iface):
    print(f"[*] Starting Integrity Attack PoC on port {port}")
    print("[*] Waiting for a valid packet...")

    pkts = sniff(iface=iface, filter=f"udp port {port}", count=1, timeout=30)
    if not pkts:
        print("[!] No packet captured.")
        return

    pkt = pkts[0]
    raw_data = bytearray(pkt[Raw].load)
    
    # Flip a bit in the payload (starting at offset 34)
    # This simulates a MITM attack trying to modify the message.
    if len(raw_data) > 35:
        original_byte = raw_data[35]
        raw_data[35] ^= 0xFF
        print(f"[+] Modified payload byte at index 35: 0x{original_byte:02x} -> 0x{raw_data[35]:02x}")
    else:
        print("[!] Packet too short to flip payload bits.")
        return

    print("[*] Sending the corrupted packet...")
    corrupted_pkt = IP(dst=pkt[IP].dst)/UDP(sport=pkt[UDP].sport, dport=port)/Raw(load=raw_data)
    send(corrupted_pkt, verbose=False)

    print("[+] Packet sent. Expected result: Silent Drop (no response, no logs in the server).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shard Integrity Attack PoC")
    parser.add_argument("--port", type=int, default=3000, help="UDP port (default: 3000)")
    parser.add_argument("--iface", type=str, default="lo", help="Interface (default: lo)")
    args = parser.parse_args()
    run_integrity_test(args.port, args.iface)
