#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复现网关重传循环：同一 iPhone ClientHello 变体反复发送，打印服务端每次响应的大小/首字节。"""
import hashlib, hmac, os, socket, struct

HOST, PORT = "127.0.0.1", 1812
SECRET = b"mytestkey"
USERNAME = b"vpn.local"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80
EAP_TYPE_TLS = 13

ID_EAP = bytes.fromhex("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e"
                       "6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c")
NAK_EAP = bytes.fromhex("02010006030d")
HELLO_EAP = bytes.fromhex(
    "020200a10d800000009716030100920100008e03036acaf67f44f70c9691c06c9092b681fe715aa2547b7a7809d9db"
    "b93bb3b73e1a00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d"
    "003c0035002f000a01000039000a00080006001700180019000b00020100000d00120010040102010501060104"
    "030203050306030005000501000000000012000000170000")


def access_request(rid, eap, uname=USERNAME):
    attrs = bytes([A_USERNAME, 2 + len(uname)]) + uname
    for i in range(0, len(eap), 253):
        c = eap[i:i + 253]
        attrs += bytes([A_EAPMSG, 2 + len(c)]) + c
    attrs += bytes([A_MA, 18]) + b"\x00" * 16
    pkt = bytes([1, rid]) + struct.pack("!H", 20 + len(attrs)) + os.urandom(16) + attrs
    ma = 20 + len(attrs) - 16
    mac = hmac.new(SECRET, pkt[:ma] + b"\x00" * 16 + pkt[ma + 16:], hashlib.md5).digest()
    return pkt[:ma] + mac + pkt[ma + 16:]


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


class Sess:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(8)
        self.rid = 1

    def send(self, eap):
        self.sock.sendto(access_request(self.rid, eap), (HOST, PORT))
        self.rid = (self.rid + 1) % 256
        return self.sock.recvfrom(65535)[0]


def describe(tag, resp):
    eap = eap_of(resp)
    if eap is None:
        print("%-28s -> 无 EAP 属性" % tag)
        return None
    code = eap[0]
    eid = eap[1]
    t = eap[4] if len(eap) > 4 else None
    data = eap[5:] if t is not None else b""
    print("%-28s -> RADIUS pkt=%dB EAP=%dB code=%d id=%d type=%s data=%dB head=%s"
          % (tag, len(resp), len(eap), code, eid, t, len(data), data[:24].hex()))
    return eap


s = Sess()
print("== 建立会话 ==")
describe("[1] Identity", s.send(ID_EAP))
describe("[2] NAK(TLS)", s.send(NAK_EAP))
r = describe("[3] ClientHello(id=2)", s.send(HELLO_EAP))

print("\n== A. 同 EAP-Id 重传（网关重传路径）==")
for i in range(3):
    describe("A%d ClientHello(id=2) 重传" % i, s.send(HELLO_EAP))

print("\n== B. 空拉取片（1 字节 0x00）==")
for i in range(3):
    describe("B%d 空拉取" % i, s.send(bytes([2, 2, 0, 6, EAP_TYPE_TLS, 0x00])))

print("\n== C. 同 ClientHello 但 EAP-Id 递增 ==")
for i in range(3, 6):
    describe("C%d ClientHello(id=%d)" % (i, i), s.send(HELLO_EAP[:1] + bytes([i]) + HELLO_EAP[2:]))

print("\n== D. 再来一轮空拉取 ==")
for i in range(3):
    describe("D%d 空拉取" % i, s.send(bytes([2, 5, 0, 6, EAP_TYPE_TLS, 0x00])))
