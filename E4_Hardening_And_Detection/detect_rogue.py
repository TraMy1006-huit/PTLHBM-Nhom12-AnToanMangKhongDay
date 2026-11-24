#!/usr/bin/env python3
from scapy.all import *

APPROVED_BSSID = ["10:7c:61:84:39:91", "10:7c:61:84:39:90"]
TARGET_SSID = "Bankstown 2.4G"
BASELINE_RSSI = -35

def detect_rogue_ap(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr3.lower()
        rssi = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None

        if ssid == TARGET_SSID and bssid not in APPROVED_BSSID:
            print(f"[ALERT - ROGUE AP DETECTED!] Dấu hiệu Lớp 1 (BSSID Mới):")
            print(f" -> SSID: {ssid} | BSSID Giả Mạo: {bssid} | RSSI: {rssi} dBm")
            ie_bytes = bytes(packet[Dot11Beacon])
            if b"\x00\x50\xf2" not in ie_bytes:
                print(f" -> [!] Dấu hiệu Lớp 2: RSN IE Fingerprint không trùng khớp!")
            if rssi and (rssi - BASELINE_RSSI > 15):
                print(f" -> [!] Dấu hiệu Lớp 3: RSSI tăng đột biến (+{rssi - BASELINE_RSSI} dBm)!")
            print("-" * 60)

print("[*] Dang khoi chay kich ban giam sat phat hien Rogue AP / Evil Twin...")
sniff(offline="E2_PCAP_Traffic/capture_E2-01.cap", prn=detect_rogue_ap, store=0)
