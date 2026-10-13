# -*- coding: utf-8 -*-
"""统计 pcap 里的流量。"""
import struct

def parse_pcap(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        magic = struct.unpack('<I', gh[:4])[0]
        endian = '>' if magic in (0xa1b2c3d4, 0xd4c3b2a1) else '<'
        pkts = []
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + 'IIII', hdr)
            data = f.read(caplen)
            if len(data) < caplen: break
            pkts.append((ts_sec, data))
        return pkts

def l2_info(data):
    # 试 SLL(16) 与 Ethernet(14)
    for l2 in (14, 16):
        if len(data) < l2 + 20 + 8: continue
        proto = (data[l2+12] << 8) | data[l2+13] if l2 == 14 else (data[l2+14] << 8) | data[l2+15]
        if proto != 0x0800: continue
        ip = data[l2:l2+20]
        ihl = (ip[0] & 0x0f) * 4
        proto2 = ip[9]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        udp = data[l2+ihl:l2+ihl+8] if proto2 == 17 and len(data) >= l2+ihl+8 else None
        sp = dp = -1
        if udp:
            sp = (udp[0] << 8) | udp[1]; dp = (udp[2] << 8) | udp[3]
        return l2, proto2, src, dst, sp, dp, len(data)
    return None

for pcap in [r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius_r28.pcap", r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_ike_r28.pcap"]:
    pkts = parse_pcap(pcap)
    print(f"=== {pcap}: {len(pkts)} 包 ===")
    from collections import Counter
    c = Counter()
    for ts, data in pkts:
        r = l2_info(data)
        if r is None:
            c[("?", len(data))] += 1
            continue
        l2, proto2, src, dst, sp, dp, ln = r
        key = (src, dst, sp, dp)
        c[key] += 1
    for k, v in c.most_common(15):
        print(f"  {k} x{v}")
