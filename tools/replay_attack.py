#!/usr/bin/env python3
"""
Shard Security Tool: Replay Attack PoC
This script captures a valid Shard packet and attempts to resend it to the server.
The server should reject the second packet due to its monotonic sequence ID (Anti-Replay).

Requirements: scapy (pip install scapy)
Usage: sudo python3 tools/replay_attack.py --port 3000
"""

from scapy.all import *
import argparse
import sys

def run_replay(port, iface):
    print(f"[*] Starting Replay Attack PoC on port {port} (iface: {iface})")
    print("[*] Status: WAITING FOR PACKET... (Run 'shard send' now)")

    try:
        # Capture 1 valid Shard UDP packet
        pkts = sniff(iface=iface, filter=f"udp port {port}", count=1, timeout=30)

        if not pkts:
            print("[!] Error: No packet captured within 30 seconds.")
            return

        pkt = pkts[0]
        raw_data = pkt[Raw].load
        seq_id = raw_data[2:10].hex()
        
        print(f"[+] Packet captured! Sequence ID: 0x{seq_id}")
        print("[*] Replaying the exact same packet to the server...")

        # Construct and send the replay packet
        replay_pkt = IP(dst=pkt[IP].dst)/UDP(sport=pkt[UDP].sport, dport=port)/Raw(load=raw_data)
        send(replay_pkt, verbose=False)

        print("[+] Replay sent. Check the server logs (it should ignore it).")

    except PermissionError:
        print("[!] Error: You must run this script with 'sudo'.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shard Replay Attack PoC")
    parser.add_argument("--port", type=int, default=3000, help="UDP port to sniff (default: 3000)")
    parser.add_argument("--iface", type=str, default="lo", help="Interface to sniff (default: lo)")
    args = parser.parse_args()
    run_replay(args.port, args.iface)
