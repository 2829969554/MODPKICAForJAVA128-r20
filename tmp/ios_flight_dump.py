#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 iPhone 原始 EAP 序列（2026-10-11 抓包）直连 1812，抓服务端完整 TLS 飞行并逐字段解析。
目的：找出 iOS / SChannel 严格客户端在收到该飞行后静默放弃的原因。"""
import hashlib, hmac, os, socket, struct, subprocess, sys

HOST, PORT = "127.0.0.1", int(os.environ.get("EAP_PORT", "1812"))
SECRET = b"mytestkey"
USERNAME = b"vpn.local"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80
EAP_TYPE_TLS = 13

ID_EAP = bytes.fromhex(
    "0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e"
    "6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e"
    "6c6f63616c")
NAK_EAP = bytes.fromhex("02010006030d")
HELLO_EAP = bytes.fromhex(
    "020200a10d800000009716030100920100008e03036acaf67f44f70c9691c06c9092b681fe715aa2547b7a78"
    "09d9dbb93bb3b73e1a00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d"
    "009c003d003c0035002f000a01000039000a00080006001700180019000b00020100000d0012001004010201"
    "0501060104030203050306030005000501000000000012000000170000")


def access_request(rid, eap):
    attrs = bytes([A_USERNAME, 2 + len(USERNAME)]) + USERNAME
    for i in range(0, len(eap), 253):
        c = eap[i:i + 253]
        attrs += bytes([A_EAPMSG, 2 + len(c)]) + c
    attrs += bytes([A_MA, 18]) + b"\x00" * 16
    pkt = bytes([1, rid]) + struct.pack("!H", 20 + len(attrs)) + os.urandom(16) + attrs
    ma_off = 20 + len(attrs) - 16
    mac = hmac.new(SECRET, pkt[:ma_off] + b"\x00" * 16 + pkt[ma_off + 16:], hashlib.md5).digest()
    return pkt[:ma_off] + mac + pkt[ma_off + 16:]


def eap_of(pkt):
    buf, i = b"", 20
    while i + 2 <= len(pkt):
        t, l = pkt[i], pkt[i + 1]
        if l < 2 or i + l > len(pkt):
            break
        if t == A_EAPMSG:
            buf += pkt[i + 2:i + l]
        i += l
    return buf or None


def send(sock, rid, eap):
    sock.sendto(access_request(rid, eap), (HOST, PORT))
    return sock.recvfrom(65535)[0]


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(6)
    rid = 1
    resp = send(sock, rid, ID_EAP)
    eap = eap_of(resp)
    print("[1] Identity → EAP type=%s id=%s" % (eap[4] if eap else None, eap[1] if eap else None))
    rid += 1
    resp = send(sock, rid, NAK_EAP)
    eap = eap_of(resp)
    print("[2] NAK(TLS) → EAP type=%s id=%s flags=0x%02x" % (eap[4], eap[1], eap[5]))
    rid += 1
    resp = send(sock, rid, HELLO_EAP)
    eap = eap_of(resp)
    print("[3] iPhone ClientHello(%dB) → EAP id=%s" % (len(HELLO_EAP), eap[1]))

    flight = b""
    total = None
    for _ in range(80):
        eap = eap_of(resp)
        if eap is None or len(eap) < 6 or eap[4] != EAP_TYPE_TLS:
            print("非 TLS 响应:", eap.hex() if eap else None)
            break
        d = eap[5:]
        flags = d[0]
        rest = d[1:]
        if flags & 0x80:
            total = struct.unpack("!I", rest[:4])[0]
            rest = rest[4:]
        flight += rest
        print("    frag EAP-Id=%d flags=0x%02x payload=%dB (累计 %dB)" % (eap[1], flags, len(rest), len(flight)))
        if not (flags & 0x40):
            break
        rid = (rid + 1) % 256
        resp = send(sock, rid, bytes([2, eap[1], 0, 6, EAP_TYPE_TLS, 0x00]))

    print("服务端飞行 %d 字节（首片声明总长 %s）" % (len(flight), total))
    open("tmp/ios_flight.bin", "wb").write(flight)

    # ---- 解析握手消息 ----
    msgs, pos = [], 0
    while pos + 5 <= len(flight):
        rlen = struct.unpack("!H", flight[pos + 3:pos + 5])[0]
        end = pos + 5 + rlen
        print("record: type=0x%02x ver=%s len=%d" % (flight[pos], flight[pos + 1:pos + 3].hex(), rlen))
        p = pos + 5
        while p + 4 <= end:
            mtype = flight[p]
            mlen = struct.unpack("!I", b"\x00" + flight[p + 1:p + 4])[0]
            msgs.append((mtype, flight[p + 4:p + 4 + mlen]))
            p += 5 + mlen
        pos = end
    names = {2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
             13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateStatus"}
    print("握手消息:", ", ".join("%s(%dB)" % (names.get(t, t), len(b)) for t, b in msgs))

    sh = [b for t, b in msgs if t == 2][0]
    p = 2 + 32
    sid_len = sh[p]; p += 1
    sid = sh[p:p + sid_len]; p += sid_len
    suite = struct.unpack("!H", sh[p:p + 2])[0]; p += 3
    extlen = struct.unpack("!H", sh[p:p + 2])[0]; p += 2
    exts = sh[p:p + extlen]
    print("ServerHello: ver=%s sid_len=%d suite=0x%04x random_tail=%r" %
          (sh[0:2].hex(), sid_len, suite, sh[34:66][-8:]))
    i = 0
    while i + 4 <= len(exts):
        et, el = struct.unpack("!HH", exts[i:i + 4])
        print("   ext 0x%04x len=%d data=%s" % (et, el, exts[i + 4:i + 4 + el].hex()))
        i += 4 + el

    cert = [b for t, b in msgs if t == 11][0]
    listlen = struct.unpack("!I", b"\x00" + cert[0:3])[0]
    chain, p = [], 3
    while p + 3 <= len(cert):
        ln = struct.unpack("!I", b"\x00" + cert[p:p + 3])[0]
        chain.append(cert[p + 3:p + 3 + ln]); p += 3 + ln
    print("Certificate: 声明链长=%d 实际 %d 张" % (listlen, len(chain)))
    for i, der in enumerate(chain):
        r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
                            "-dates", "-serial", "-ext", "keyUsage,extendedKeyUsage,basicConstraints,subjectAltName"],
                           input=der, capture_output=True, text=True)
        print("=== 证书[%d] (%dB) ===" % (i, len(der)))
        print(r.stdout.strip())
        if r.stderr.strip():
            print("  [openssl] " + r.stderr.strip())
        open("tmp/ios_chain_%d.der" % i, "wb").write(der)

    # ---- CertificateRequest ----
    cr = [b for t, b in msgs if t == 13]
    if cr:
        cr = cr[0]
        p = 1  # cert types len
        ntypes = cr[0]; p += 1
        types = cr[p:p + ntypes]; p += ntypes
        sal = struct.unpack("!H", cr[p:p + 2])[0]; p += 2
        algs = [struct.unpack("!H", cr[p + k:p + k + 2])[0] for k in range(0, sal, 2)]
        p += sal
        cal = struct.unpack("!H", cr[p:p + 2])[0]; p += 2
        print("CertReq: cert_types=%s sig_algs=%d种 %s CA列表=%dB" %
              (list(types), len(algs), " ".join("%04x" % a for a in algs), cal))
    # ---- SKE ----
    ske = [b for t, b in msgs if t == 12]
    if ske:
        ske = ske[0]
        pklen = ske[3]
        print("SKE: curve=0x%04x pubkey=%dB sigalg=0x%04x siglen=%d" %
              (struct.unpack("!H", ske[1:3])[0], pklen,
               struct.unpack("!H", ske[4 + pklen:6 + pklen])[0],
               struct.unpack("!H", ske[6 + pklen:8 + pklen])[0]))


main()
