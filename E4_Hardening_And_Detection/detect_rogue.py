#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kich ban phat hien diem truy cap gia mao (Rogue AP / Evil Twin) qua 3 lop chi bao
De tai 16: Phan tich va danh gia an toan mang khong day - Nhom 12 (HUIT)
"""
import sys
from scapy.all import *

APPROVED_BSSID = ["10:7c:61:84:39:91", "10:7c:61:84:39:90"]
TARGET_SSID = "Bankstown 2.4G"
BASELINE_RSSI = -35

if "--simulate-rogue" in sys.argv:
    APPROVED_BSSID = ["00:11:22:33:44:55"]

def detect_rogue_ap(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr3.lower()
        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None

        if ssid == TARGET_SSID and bssid not in APPROVED_BSSID:
            print("[ALERT - ROGUE AP DETECTED!] Dau hieu Lop 1 (BSSID Moi):")
            print(f" -> SSID: {ssid} | BSSID Gia Mao: {bssid} | RSSI: {rssi} dBm")
            ie_bytes = bytes(packet[Dot11Beacon])
            if b"\x00\x50\xf2" not in ie_bytes:
                print(" -> [!] Dau hieu Lop 2: RSN IE Fingerprint khong trung khop!")
            if rssi and (rssi - BASELINE_RSSI > 15):
                print(f" -> [!] Dau hieu Lop 3: RSSI tang dot bien (+{rssi - BASELINE_RSSI} dBm)!")
            print("-" * 65)

if __name__ == "__main__":
    print("[*] Dang khoi chay kich ban giam sat phat hien Rogue AP / Evil Twin...")
    sniff(offline="E2_PCAP_Traffic/capture_E2-01.cap", prn=detect_rogue_ap, store=0)
