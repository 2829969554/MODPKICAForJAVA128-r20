# -*- coding: utf-8 -*-
import struct

def parse_pcap(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        magic = struct.unpack('<I', gh[:4])[0]
        endian = '<' if magic == 0xa1b2c3d4 else '>'
        pkts = []
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + 'IIII', hdr)
            data = f.read(caplen)
            if len(data) < caplen: break
            pkts.append((ts_sec, data))
        return pkts

pkts = parse_pcap(r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius_r28.pcap")
print("包数:", len(pkts))
for i in range(5):
    ts, data = pkts[i]
    print(f"pkt{i} len={len(data)} head={data[:48].hex()}")
