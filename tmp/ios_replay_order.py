#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证：客户端拉完分片后再次重传 ClientHello，服务端重发的是"首片"还是"末片"？"""
import hashlib, hmac, os, socket, struct

HOST, PORT = "127.0.0.1", 1812
SECRET = b"mytestkey"
USERNAME = b"vpn.local"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80

ID_EAP = bytes.fromhex("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e"
                       "6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c")
NAK_EAP = bytes.fromhex("02010006030d")
HELLO_EAP = bytes.fromhex(
    "020200a10d800000009716030100920100008e03036acaf67f44f70c9691c06c9092b681fe715aa2547b7a7809d9db"
    "b93bb3b73e1a00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d"
    "003c0035002f000a01000039000a00080006001700180019000b00020100000d00120010040102010501060104"
    "030203050306030005000501000000000012000000170000")


def access_request(rid, eap):
    attrs = bytes([A_USERNAME, 2 + len(USERNAME)]) + USERNAME
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


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)
rid = [1]


def send(eap):
    sock.sendto(access_request(rid[0], eap), (HOST, PORT))
    rid[0] = (rid[0] + 1) % 256
    return sock.recvfrom(65535)[0]


def show(tag, resp):
    eap = eap_of(resp)
    if eap is None or len(eap) < 5:
        print("%-42s -> code=%s EAP=%dB" % (tag, eap[0] if eap else "-", len(eap or b"")))
        return None
    data = eap[5:]
    print("%-42s -> code=%d id=%d flags=0x%02x data=%dB  head=%s"
          % (tag, eap[0], eap[1], data[0] if data else -1, len(data), data[:20].hex()))
    return data


send(ID_EAP); send(NAK_EAP)
d1 = show("[1] ClientHello(首次)", send(HELLO_EAP))
d2 = show("[2] 空拉取 #1（取第2片）", send(bytes([2, 2, 0, 6, 13, 0x00])))
d3 = show("[3] 空拉取 #2（取第3片）", send(bytes([2, 2, 0, 6, 13, 0x00])))
d4 = show("[4] 空拉取 #3（服务端已无数据）", send(bytes([2, 2, 0, 6, 13, 0x00])))
print()
print("首片 head :", (d1 or b"")[:20].hex())
print("末片 head :", (d3 or b"")[:20].hex())
print()
r = show("[5] ★ 重传 ClientHello（同 EAP-Id）", send(HELLO_EAP))
if r is not None:
    first_head = (d1 or b"")[:20]
    last_head = (d3 or b"")[:20]
    print("    重发内容与原首片一致? %s" % (r[:20] == first_head))
    print("    重发内容与原末片一致? %s" % (r[:20] == last_head))
