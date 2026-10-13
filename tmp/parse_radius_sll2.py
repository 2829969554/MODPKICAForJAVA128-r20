# -*- coding: utf-8 -*-
"""解析 RADIUS pcap（SLL2 头 20B）。提取服务端(10.255.228.55)->网关 Access-Challenge 的 EAP 内容。"""
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

def udp_payload(data):
    # SLL2: 20B
    if len(data) < 20 + 20 + 8: return None
    proto = (data[14] << 8) | data[15]
    if proto != 0x0800: return None
    ip = data[20:40]
    ihl = (ip[0] & 0x0f) * 4
    if ip[9] != 17: return None
    src_ip, dst_ip = ip[12:16], ip[16:20]
    udp = data[20+ihl:20+ihl+8]
    sport = (udp[0] << 8) | udp[1]
    dport = (udp[2] << 8) | udp[3]
    return src_ip, dst_ip, sport, dport, data[20+ihl+8:]

SRV = bytes([10,255,228,55])
GW  = bytes([10,255,228,225])

def show_eap(payload, rel):
    if len(payload) < 20: return None
    code, ident = payload[0], payload[1]
    length = (payload[2] << 8) | payload[3]
    attrs = []
    off = 20
    while off + 2 <= length and off + 2 <= len(payload):
        t, al = payload[off], payload[off+1]
        if al < 2 or off + al > length: break
        attrs.append((t, payload[off+2:off+al]))
        off += al
    eap = b"".join(v for t, v in attrs if t == 79)
    if not eap: 
        return f"[t={rel:>5}s] R{code} rid={ident} len={length} no-EAP"
    ec = eap[0]; eid = eap[1]; elen = (eap[2]<<8)|eap[3]
    etype = eap[4] if elen > 4 and len(eap) > 4 else -1
    tls_part = eap[5:] if len(eap) > 5 else b""
    flags = tls_part[0] if tls_part else -1
    total = -1
    if tls_part and (flags & 0x80) and len(tls_part) >= 5:
        total = (tls_part[1]<<24)|(tls_part[2]<<16)|(tls_part[3]<<8)|tls_part[4]
    mark = ""
    if tls_part and len(tls_part) > 5 and tls_part[0] == 0x16:
        mark = f" HS={tls_part[5]:#04x}"
    elif tls_part and len(tls_part) > 5 and tls_part[0] == 0x14:
        mark = " CCS"
    elif tls_part and len(tls_part) > 5 and tls_part[0] == 0x15:
        mark = " ALERT"
    head = tls_part[5:22].hex() if len(tls_part) > 5 else tls_part.hex()
    return (f"[t={rel:>5}s] R{code} rid={ident} EAP(c={ec} id={eid} len={elen} type={etype}) "
            f"TLS(flags=0x{flags:02x} tot={total} n={len(tls_part)}) head={head}{mark}")

for pcap in [r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius_r28.pcap"]:
    pkts = parse_pcap(pcap)
    print(f"{pcap}: {len(pkts)} 包")
    first_ts = None
    n = 0
    for ts, data in pkts:
        r = udp_payload(data)
        if r is None: continue
        src, dst, sp, dp, payload = r
        if first_ts is None: first_ts = ts
        rel = ts - first_ts
        if dst == GW and dp in (1812, 1813) and len(payload) >= 20:
            line = show_eap(payload, rel)
            if line:
                print(line)
                n += 1
                if n > 40: break
    print(f"--- 共 {n} 条 ---")
