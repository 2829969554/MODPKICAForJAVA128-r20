# -*- coding: utf-8 -*-
"""下载 pcap 到本地并用纯 Python 解析：
   1) 1812 Access-Challenge 的 EAP-Message 属性
   2) 4500 IKE_AUTH[R] 的 EAP 载荷 -> EAP 消息
   输出两者字节对比。"""
import paramiko, sys, io, struct
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
sftp = cli.open_sftp()
sftp.get('/tmp/ios_radius.pcap', r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius.pcap')
sftp.close(); cli.close()
print("pcap 已下载，大小:", __import__('os').path.getsize(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius.pcap'))

def parse_pcap(path):
    data = open(path, 'rb').read()
    if data[:4] != b'\xd4\xc3\xb2\xa1' and data[:4] != b'\xa1\xb2\xc3\xd4':
        print("非 pcap 格式"); return
    little = data[:4] == b'\xd4\xc3\xb2\xa1'
    off = 24  # 跳过全局头
    pkts = []
    while off + 16 <= len(data):
        if little:
            ts_sec, ts_usec, incl, orig = struct.unpack_from('<IIII', data, off)
        else:
            ts_sec, ts_usec, incl, orig = struct.unpack_from('>IIII', data, off)
        off += 16
        frame = data[off:off+incl]
        off += incl
        pkts.append((ts_sec, ts_usec, frame))
    return pkts

pkts = parse_pcap(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\ios_radius.pcap')
print("包数:", len(pkts))

# 调试：打印前 5 包的链路层与 IP 摘要
for i, (ts, us, f) in enumerate(pkts[:5]):
    print(f"pkt{i}: len={len(f)} eth={f[:14].hex()}")

# 找出 1812 的 Access-Challenge 和 4500 的 IKE_AUTH[R]
found_chal = 0
for ts, us, f in pkts:
    if len(f) < 40: continue
    ip_off = 16  # SLL
    if ip_off + 20 > len(f): continue
    if f[ip_off] >> 4 != 4: continue
    ihl = (f[ip_off] & 0x0f) * 4
    if ip_off + ihl + 8 > len(f): continue
    proto = f[ip_off+9]
    src = '.'.join(str(b) for b in f[ip_off+12:ip_off+16])
    dst = '.'.join(str(b) for b in f[ip_off+16:ip_off+20])
    if proto != 17: continue
    sport, dport = struct.unpack_from('>HH', f, ip_off+ihl)
    udp_len = struct.unpack_from('>H', f, ip_off+ihl+4)[0]
    if ip_off+ihl+8+udp_len-8 > len(f): continue
    payload = f[ip_off+ihl+8: ip_off+ihl+udp_len]
    # RADIUS 1812 入向 Access-Challenge（服务端源端口 1812）
    if sport == 1812 and len(payload) > 20:
        code = payload[0]
        if code == 11:  # Access-Challenge
            found_chal += 1
            if found_chal < 3: continue  # 看第3个（ClientHello 对应的 290B）
            length = struct.unpack_from('>H', payload, 2)[0]
            attrs = payload[20:length]
            print(f"\n[Access-Challenge] ts={ts}.{us} len={length}")
            # 遍历属性找 EAP-Message(79)
            i = 0
            while i < len(attrs):
                t, l = attrs[i], attrs[i+1]
                val = attrs[i+2:i+l]
                if t == 79:
                    print(f"  EAP-Message attr len={len(val)} hex={val.hex()}")
                elif t == 24:
                    print(f"  State attr len={len(val)}")
                elif t == 26:
                    print(f"  Vendor-Specific len={len(val)}")
                else:
                    print(f"  attr type={t} len={l}")
                i += l
            break

# 4500 IKE_AUTH[R]（GW->iOS 出向）EAP 载荷
for ts, us, f in pkts:
    if len(f) < 42: continue
    ip_off = 14 if f[12:14] == b'\x08\x00' else 16
    if f[ip_off] >> 4 != 4: continue
    ihl = (f[ip_off] & 0x0f) * 4
    proto = f[ip_off+9]
    src = '.'.join(str(b) for b in f[ip_off+12:ip_off+16])
    dst = '.'.join(str(b) for b in f[ip_off+16:ip_off+20])
    if proto != 17: continue
    sport, dport = struct.unpack_from('>HH', f, ip_off+ihl)
    udp_len = struct.unpack_from('>H', f, ip_off+ihl+4)[0]
    payload = f[ip_off+ihl+8: ip_off+ihl+udp_len]
    if dport == 4500 and sport == 4500 and src == '10.255.228.225' and dst == '10.255.228.120':
        if len(payload) < 32: continue
        ike = payload[4:]  # 去 4B non-ESP 标记
        if len(ike) < 28: continue
        nextp, ver, exch, flags = ike[0], ike[1], ike[2], ike[3]
        msgid = struct.unpack_from('>I', ike, 4)[0]
        ike_len = struct.unpack_from('>H', ike, 8)[0]
        if exch != 0x23: continue  # IKE_AUTH
        # 遍历载荷
        p = 28
        np = nextp
        while p + 4 <= len(ike):
            nxt = ike[p]
            crit = ike[p+1]
            l = struct.unpack_from('>H', ike, p+2)[0]
            body = ike[p+4:p+l]
            if np == 0x2e:  # EAP payload
                eap = body
                print(f"\n[IKE_AUTH[R]] ts={ts}.{us} ike_len={ike_len} msgid={msgid}")
                print(f"  EAP 载荷 len={l} (含4B头) -> EAP 消息 {len(eap)}B")
                print(f"  EAP 头: code={eap[0]} id={eap[1]} eap_len={struct.unpack_from('>H', eap, 2)[0]} type={eap[4] if len(eap)>4 else '?'} flags={eap[5] if len(eap)>5 else '?'}")
                print(f"  EAP 前 60B: {eap[:60].hex()}")
                print(f"  EAP 尾部 20B: {eap[-20:].hex()}")
                break
            if l == 0: break
            p += l
            np = nxt
        break
