#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证：网关/IKE 层重传的空拉取片（1B 0x00）是否被当作"新拉取"而跳片。"""
import hashlib, hmac, os, socket, struct
HOST, PORT = "127.0.0.1", 1812
SECRET=b"mytestkey"; USERNAME=b"vpn.local"; A_USERNAME,A_EAPMSG,A_MA=1,79,80
ID_EAP=bytes.fromhex("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e"
  "6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c")
NAK_EAP=bytes.fromhex("02010006030d")
HELLO=bytes.fromhex("020200a10d800000009716030100920100008e03036acaf67f44f70c9691c06c9092b681fe715aa2547b7a7809d9db"
  "b93bb3b73e1a00002c00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d"
  "003c0035002f000a01000039000a00080006001700180019000b00020100000d00120010040102010501060104"
  "030203050306030005000501000000000012000000170000")
def req(rid,e):
    a=bytes([A_USERNAME,2+len(USERNAME)])+USERNAME
    for i in range(0,len(e),253):
        c=e[i:i+253]; a+=bytes([A_EAPMSG,2+len(c)])+c
    a+=bytes([A_MA,18])+b"\x00"*16
    p=bytes([1,rid])+struct.pack("!H",20+len(a))+os.urandom(16)+a; m=20+len(a)-16
    return p[:m]+hmac.new(SECRET,p[:m]+b"\x00"*16+p[m+16:],hashlib.md5).digest()+p[m+16:]
def eap_of(p):
    b,i=b"",20
    while i+2<=len(p):
        t,l=p[i],p[i+1]
        if l<2 or i+l>len(p): break
        if t==A_EAPMSG: b+=p[i+2:i+l]
        i+=l
    return b or None
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(8); rid=[1]
def send(e):
    s.sendto(req(rid[0],e),(HOST,PORT)); rid[0]=(rid[0]+1)%256; return s.recvfrom(65535)[0]
def show(tag,r):
    e=eap_of(r); d=e[5:] if e and len(e)>5 else b""
    print("%-46s -> code=%d id=%d flags=0x%02x data=%dB head=%s"%(tag,e[0] if e else -1,e[1] if e else -1,
        d[0] if d else -1,len(d),(d[:16].hex() if d else "")))
    return d
send(ID_EAP); send(NAK_EAP)
f1=show("[1] ClientHello", send(HELLO))
f2=show("[2] 拉取#1（EAP-Id=2）", send(bytes([2,2,0,6,13,0x00])))
f2b=show("[3] ★重传同一拉取（EAP-Id=2，逐字节相同）", send(bytes([2,2,0,6,13,0x00])))
f3=show("[4] 再拉取（EAP-Id=3）", send(bytes([2,3,0,6,13,0x00])))
f4=show("[5] 再拉取（EAP-Id=4）", send(bytes([2,4,0,6,13,0x00])))
print()
print("首片=%s..."%f1[:12].hex())
print("第2片=%s...   重传拉取的响应=%s..."%(f2[:12].hex(),f2b[:12].hex()))
print("第3片=%s..."%f3[:12].hex())
print("→ 重传拉获取到的是【%s】"%("上一片（正确重放）" if f2b[:12]==f2[:12] else ("下一片（跳片!）" if f2b[:12]==f3[:12] else "未知")))
