# -*- coding: utf-8 -*-
import struct
for pcap in [r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius_r28.pcap"]:
    with open(pcap, 'rb') as f:
        gh = f.read(24)
        print("magic:", gh[:4].hex(), struct.unpack('<I', gh[:4])[0], struct.unpack('>I', gh[:4])[0])
        print("version:", gh[4:8].hex())
        # 手动读第一个包
        hdr = f.read(16)
        print("pkt hdr:", hdr.hex())
        if len(hdr) == 16:
            ts_sec, ts_usec, caplen, origlen = struct.unpack('<IIII', hdr)
            print(f"LE: ts={ts_sec} caplen={caplen} origlen={origlen}")
            ts_sec2, ts_usec2, caplen2, origlen2 = struct.unpack('>IIII', hdr)
            print(f"BE: ts={ts_sec2} caplen={caplen2} origlen={origlen2}")
