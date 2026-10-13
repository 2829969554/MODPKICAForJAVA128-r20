#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用"同时提议 TLS1.3+TLS1.2"的 ClientHello 抓服务端飞行并做完整性/一致性校验。"""
import hashlib, hmac, os, socket, struct, sys

HOST, PORT = "127.0.0.1", 1812
SECRET = b"mytestkey"; IDENTITY = b"tls:admin666"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80

def client_hello(offer13, groups=(0x001D,0x0017,0x0018), suites=(0xC02F,0xC02B,0x009C)):
    rnd = os.urandom(32)
    s = struct.pack("!H", len(suites)*2) + b"".join(struct.pack("!H",c) for c in suites)
    exts = b""
    exts += struct.pack("!HH",0x000A,2+len(groups)*2)+struct.pack("!H",len(groups)*2)+b"".join(struct.pack("!H",g) for g in groups)
    exts += struct.pack("!HH",0x000B,2)+b"\x01\x00"
    sa = struct.pack("!HHHHH",0x0401,0x0501,0x0601,0x0403,0x0201)
    exts += struct.pack("!HH",0x000D,2+len(sa))+struct.pack("!H",len(sa))+sa
    exts += struct.pack("!HH",0x0017,0)
    if offer13:
        exts += struct.pack("!HH",0x002B,5)+bytes([4,0x03,0x04,0x03,0x03])
        exts += struct.pack("!HH",0x0033,2+len(groups)*2)+struct.pack("!H",len(groups)*2)+b"".join(struct.pack("!H",g) for g in groups)
    body = b"\x03\x03"+rnd+b"\x00"+s+b"\x01\x00"+struct.pack("!H",len(exts))+exts
    msg = b"\x01"+struct.pack("!I",len(body))[1:]+body
    return msg, bytes([0x16,0x03,0x01])+struct.pack("!H",len(msg))+msg

def eap(code, eid, t=None, data=b""):
    if t is None: return bytes([code,eid])+struct.pack("!H",4)+data
    b=bytes([t])+data; return bytes([code,eid])+struct.pack("!H",4+len(b))+b

def req(rid, eapbytes):
    attrs=bytes([A_USERNAME,2+len(IDENTITY)])+IDENTITY
    for i in range(0,len(eapbytes),253):
        c=eapbytes[i:i+253]; attrs+=bytes([A_EAPMSG,2+len(c)])+c
    attrs+=bytes([A_MA,18])+b"\x00"*16
    pkt=bytes([1,rid])+struct.pack("!H",20+len(attrs))+os.urandom(16)+attrs
    ma=20+len(attrs)-16
    mac=hmac.new(SECRET,pkt[:ma]+b"\x00"*16+pkt[ma+16:],hashlib.md5).digest()
    return pkt[:ma]+mac+pkt[ma+16:]

def eap_of(pkt):
    buf,i=b"",20
    while i+2<=len(pkt):
        t,l=pkt[i],pkt[i+1]
        if l<2 or i+l>len(pkt): break
        if t==A_EAPMSG: buf+=pkt[i+2:i+l]
        i+=l
    return buf or None

def run(offer13, groups, suites=(0xC02F,0xC02B,0x009C)):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.settimeout(6)
    rid=7; send=lambda e:(sock.sendto(req(rid,e),(HOST,PORT)), sock.recvfrom(65535)[0])[1]
    send(eap(2,0,1,IDENTITY)); rid+=1
    msg,rec=client_hello(offer13,groups,suites)
    resp=send(eap(2,1,13,b"\x80"+struct.pack("!I",len(rec))+rec)); rid+=1
    flight=b""; total=None; nfrag=0
    for _ in range(80):
        e=eap_of(resp); d=e[5:]; flags=d[0]; rest=d[1:]
        if flags&0x80: total=struct.unpack("!I",rest[:4])[0]; rest=rest[4:]
        flight+=rest; nfrag+=1
        if not (flags&0x40): break
        resp=send(eap(2,e[1],13,b"\x00")); rid+=1
    print("  分片数=%d 实际飞行=%dB 声明总长=%s 一致=%s"%(nfrag,len(flight),total,len(flight)==total))
    # 解析
    msgs,pos=[],0
    while pos+5<=len(flight):
        rlen=struct.unpack("!H",flight[pos+3:pos+5])[0]; end=pos+5+rlen; p=pos+5
        while p+4<=end:
            mt=flight[p]; ml=struct.unpack("!I",b"\x00"+flight[p+1:p+4])[0]
            msgs.append((mt,flight[p+4:p+4+ml])); p+=5+ml
        pos=end
    names={2:"SH",11:"Cert",12:"SKE",13:"CertReq",14:"SHDone"}
    print("  消息:", ", ".join("%s(%dB)"%(names.get(t,t),len(b)) for t,b in msgs))
    sh=[b for t,b in msgs if t==2][0]
    suite=struct.unpack("!H",sh[35:37])[0]
    print("  ServerHello 版本=%s 套件=0x%04x 客户端提议=%s 选中在被提议内=%s"%(
        sh[0:2].hex(),suite,[hex(c) for c in suites],suite in suites))
    print("  随机尾8B=%r 含DOWNGRD=%s"%(sh[34:66][-8:], b"DOWNGRD" in sh[34:66]))
    ske=[b for t,b in msgs if t==12]
    if ske:
        pk=ske[0][3]
        print("  SKE 曲线=0x%04x 客户端组=%s 在被提议内=%s"%(
            struct.unpack("!H",ske[0][1:3])[0],[hex(g) for g in groups],
            struct.unpack("!H",ske[0][1:3])[0] in groups))
    return flight

for offer13,groups,tag in [(False,(0x0017,0x0018,0x0019),"仅TLS1.2（模拟旧客户端）"),
                           (True,(0x0017,0x0018,0x0019),"TLS1.3+1.2（无x25519）"),
                           (True,(0x001D,0x0017,0x0018),"TLS1.3+1.2（含x25519）")]:
    print("== %s =="%tag)
    try: run(offer13,groups)
    except Exception as ex: print("  异常:",ex)
