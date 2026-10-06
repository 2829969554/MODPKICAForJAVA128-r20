# -*- coding: utf-8 -*-
"""RADIUS 1812 明文抓包器（Linux AF_PACKET，root 运行）。
抓取 192.168.1.42 与 192.168.1.6 之间 UDP 1812/1813 流量，解析 RADIUS 属性
并打印 EAP-Message(Type=79)/User-Name(1)/Message-Authenticator(80)。
也统计 UDP 500/4500 的 IKE 报文方向（判断客户端是否回包）。
输出: /tmp/radius_capture.txt
"""
import socket, struct, time, sys, os

CAPTURE_FILE = "/tmp/radius_capture.txt"
STOP_FILE = "/tmp/radius_capture.stop"

def log(msg):
    line = time.strftime("%H:%M:%S") + " " + msg
    print(line, flush=True)
    with open(CAPTURE_FILE, "a") as f:
        f.write(line + "\n")

# 解析 RADIUS 报文
def parse_radius(data):
    if len(data) < 20:
        return None
    code = data[0]
    rlen = struct.unpack("!H", data[2:4])[0]
    auth = data[4:20].hex()
    attrs = []
    pos = 20
    while pos + 2 <= rlen and pos < len(data):
        t = data[pos]
        l = data[pos + 1]
        if l < 2 or pos + l > len(data) or pos + l > rlen:
            break
        v = data[pos + 2:pos + l]
        attrs.append((t, l, v.hex() if t not in (1,) else v.decode("utf-8", "replace")))
        pos += l
    code_names = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge"}
    return code_names.get(code, str(code)), rlen, auth, attrs

def main():
    os.makedirs("/tmp", exist_ok=True)
    try:
        os.remove(CAPTURE_FILE)
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    log("RADIUS 抓包器已启动 (Ctrl-C 或 touch %s 停止)" % STOP_FILE)
    try:
        os.remove(STOP_FILE)
    except FileNotFoundError:
        pass
    while True:
        if os.path.exists(STOP_FILE):
            log("检测到停止标记，退出")
            break
        sock.settimeout(1.0)
        try:
            pkt, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        # 以太网帧: dst(6)+src(6)+type(2)
        if len(pkt) < 42:
            continue
        eth_type = struct.unpack("!H", pkt[12:14])[0]
        if eth_type != 0x0800:  # IPv4
            continue
        ip = pkt[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0f) * 4
        proto = ip[9]
        if proto != 17:  # UDP
            continue
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport, ulen = struct.unpack("!HHH", udp[0:6])
        payload = udp[8:]
        if sport in (1812, 1813) or dport in (1812, 1813):
            direction = "→REQ" if dport in (1812, 1813) else "←RESP"
            pr = parse_radius(payload)
            if pr:
                cname, rlen, auth, attrs = pr
                line = "RADIUS %s %s %s id-len=%d auth=%s" % (direction, cname, src_ip + ":" + str(sport) + "→" + dst_ip + ":" + str(dport), rlen, auth)
                log(line)
                for (t, l, v) in attrs:
                    if t == 1:
                        log("   User-Name = %s" % v)
                    elif t == 79:
                        log("   EAP-Message[%d] = %s" % (l, v))
                    elif t == 24:
                        log("   State[%d] = %s" % (l, v))
                    elif t == 26:
                        log("   VSA[%d] = %s" % (l, v[:160]))
                    elif t == 80:
                        log("   Msg-Auth[%d] = %s" % (l, v))
                    else:
                        log("   Attr[%d/%d] = %s" % (t, l, v[:160]))
        elif sport in (500, 4500) or dport in (500, 4500):
            direction = "→IKE" if dport in (500, 4500) else "←IKE"
            log("IKE  %s %s:%d→%s:%d len=%d" % (direction, src_ip, sport, dst_ip, dport, len(payload)))

if __name__ == "__main__":
    main()
