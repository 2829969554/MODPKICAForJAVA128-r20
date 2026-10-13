# -*- coding: utf-8 -*-
import struct
from collections import Counter

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

def udp_payload(data):
    for l2 in (14, 16):
        if len(data) < l2 + 20 + 8: continue
        proto = (data[l2+12] << 8) | data[l2+13] if l2 == 14 else (data[l2+14] << 8) | data[l2+15]
        if proto != 0x0800: continue
        ip = data[l2:l2+20]
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 17: continue
        src_ip, dst_ip = ip[12:16], ip[16:20]
        udp = data[l2+ihl:l2+ihl+8]
        sport = (udp[0] << 8) | udp[1]
        dport = (udp[2] << 8) | udp[3]
        return src_ip, dst_ip, sport, dport, data[l2+ihl+8:]
    return None

pkts = parse_pcap(r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius_r28.pcap")
c = Counter()
for ts, data in pkts:
    r = udp_payload(data)
    if r is None:
        c[("?",)] += 1
        continue
    src, dst, sp, dp, payload = r
    s = ".".join(str(b) for b in src); d = ".".join(str(b) for b in dst)
    key = (s, d, sp, dp, len(payload))
    c[key] += 1
for k, v in c.most_common(20):
    print(f"  {k} x{v}")
