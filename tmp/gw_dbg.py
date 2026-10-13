# -*- coding: utf-8 -*-
"""调试：打印前 40 个 UDP 包的端口/方向，确认 SLL 偏移与过滤条件。"""
import struct

data = open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius.pcap', 'rb').read()
off = 24
n = 0
while off + 16 <= len(data) and n < 60:
    ts_sec, ts_usec, incl, orig = struct.unpack_from('<IIII', data, off)
    off += 16
    f = data[off:off+incl]
    off += incl
    if len(f) < 16: continue
    # 尝试 SLL (16B)
    if f[14:16] == b'\x08\x00':
        ip_off = 16
    else:
        ip_off = 14 if f[12:14] == b'\x08\x00' else None
    if ip_off is None or ip_off + 20 > len(f):
        continue
    v = f[ip_off]
    if v >> 4 != 4: continue
    ihl = (v & 0x0f) * 4
    if ip_off + ihl + 8 > len(f): continue
    proto = f[ip_off+9]
    if proto != 17: continue
    sport, dport = struct.unpack_from('>HH', f, ip_off+ihl)
    src = '.'.join(str(b) for b in f[ip_off+12:ip_off+16])
    dst = '.'.join(str(b) for b in f[ip_off+16:ip_off+20])
    udp_len = struct.unpack_from('>H', f, ip_off+ihl+4)[0]
    n += 1
    print(f"{n:2d} {ts_sec}.{us:06d} {src}:{sport} -> {dst}:{dport} udplen={udp_len} ipoff={ip_off}")
