# -*- coding: utf-8 -*-
# 解析 radius_win11.pcap：SLL2(20B) -> IPv4 -> UDP -> RADIUS -> EAP-Message
import struct

PCAP = r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\radius_win11.pcap"

def parse_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    little = data[:4] == b"\xd4\xc3\xb2\xa1"
    network = struct.unpack("<I" if little else ">I", data[20:24])[0]
    pkts = []
    off = 24
    while off + 16 <= len(data):
        if little:
            ts_sec, ts_usec, caplen, origlen = struct.unpack("<IIII", data[off:off+16])
        else:
            ts_sec, ts_usec, caplen, origlen = struct.unpack(">IIII", data[off:off+16])
        pkts.append((ts_sec, ts_usec, data[off+16:off+16+caplen]))
        off += 16 + caplen
    return network, pkts

network, pkts = parse_pcap(PCAP)
print("linktype=%d 包数=%d" % (network, len(pkts)))

def ip_udp(pkt):
    ip = pkt[20:]  # SLL2
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    sport, dport, ulen = struct.unpack(">HHH", ip[ihl:ihl+6])
    return src, sport, dst, dport, ip[ihl+8:]

for i, (ts, us, pkt) in enumerate(pkts):
    r = ip_udp(pkt)
    if not r:
        print("[%d] t=%d.%06d len=%d 非UDP/IPv4" % (i, ts, us, len(pkt)))
        continue
    src, sport, dst, dport, pl = r
    if len(pl) < 20:
        print("[%d] t=%d.%06d %s:%d->%s:%d UDP len=%d" % (i, ts, us, src, sport, dst, dport, len(pl)))
        continue
    code = pl[0]; ident = pl[1]; rlen = struct.unpack(">H", pl[2:4])[0]
    cn = {1:"Access-Request",2:"Access-Accept",3:"Access-Reject",11:"Access-Challenge"}.get(code, code)
    print("=" * 100)
    print("[%d] t=%d.%06d %s:%d -> %s:%d RADIUS %s id=%d rlen=%d" % (i, ts, us, src, sport, dst, dport, cn, ident, rlen))
    pos = 20
    eaps = []
    while pos + 2 <= len(pl):
        atype, alen = pl[pos], pl[pos+1]
        if alen < 2 or pos + alen > len(pl): break
        aval = pl[pos+2:pos+alen]
        if atype == 79:
            eaps.append(aval)
            print("    EAP-Message AVP len=%d: %s" % (len(aval), aval.hex()))
        pos += alen
    # 解析 EAP 头
    for e in eaps:
        if len(e) < 4: continue
        code2, eid, elen = e[0], e[1], struct.unpack(">H", e[2:4])[0]
        cn2 = {1:"Request",2:"Response",3:"Success",4:"Failure"}.get(code2, code2)
        print("    EAP %s id=%d len=%d" % (cn2, eid, elen))
        if len(e) >= 5 and e[4] == 13:  # EAP-TLS
            t = e[5:]
            flags = t[0] if len(t) > 0 else -1
            frag = ""
            if flags >= 0:
                bits = []
                if flags & 0x80: bits.append("L")
                if flags & 0x40: bits.append("M")
                if flags & 0x20: bits.append("S")
                if flags & 0x1F: bits.append("res=0x%x" % (flags & 0x1F))
                frag = "|".join(bits)
                off = 1
                total = None
                if flags & 0x80:
                    total = struct.unpack(">I", t[1:5])[0]
                    off = 5
                tls = t[off:]
                print("      EAP-TLS flags=0x%02x (%s) total=%s tlsData=%dB" % (flags, frag, total if total else "无L", len(tls)))
                print("      TLS hex: %s" % tls.hex())
    print()
