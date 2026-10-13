#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""找出服务端 SKE 签名到底是哪把私钥产生的：
   用 PKI 下所有 RSA 公钥逐一解密签名，检查是否得到 PKCS#1 v1.5 结构，
   并用多种候选"待签数据"匹配 DigestInfo。
"""
import glob
import hashlib
import os
import struct
import subprocess

import eaptls_verify as probe  # 需与本文件同目录（EAP_TLS 抓包/解析工具）

BASE = "C:/Users/28299/Desktop/modpkica4JAVA"


def pub_from_key(path):
    """从私钥文件取 (n, e)。"""
    if path.endswith(".key"):
        out = subprocess.run(["openssl", "rsa", "-in", path, "-noout", "-modulus"],
                             capture_output=True).stdout.decode(errors="replace").strip()
        if "Modulus=" not in out:
            return None
        n = int(out.split("=")[1], 16)
        txt = subprocess.run(["openssl", "rsa", "-in", path, "-noout", "-text"],
                             capture_output=True).stdout.decode(errors="replace")
        e = 65537
        for line in txt.splitlines():
            if "publicExponent" in line:
                v = line.split(":")[1].strip()
                e = int(v.split("(")[1].rstrip(")"), 16) if "(" in v else int(v)
        return n, e
    return None


def digest_info(md, h):
    oid = {"sha1": "300d06091403022 6 0500".replace(" ", ""),
           "sha256": "300d06096086480165030402010500",
           "sha384": "300d06096086480165030402020500",
           "sha512": "300d06096086480165030402030500"}[md]
    inner = bytes.fromhex(oid) + bytes([4, len(h)]) + h
    return bytes([0x30, len(inner)]) + inner


def main():
    ch_msg, flight = probe.run(False)
    msgs = probe.parse_msgs(flight)
    sh = [b for t, b in msgs if t == 2][0]
    rnd_s = sh[2:34]
    sid = sh[34]
    p = 35 + sid
    exts_len = struct.unpack("!H", sh[p + 3:p + 5])[0]
    cert = [b for t, b in msgs if t == 11][0]
    ln = struct.unpack("!I", b"\x00" + cert[3:6])[0]
    leaf = cert[6:6 + ln]
    ske = [b for t, b in msgs if t == 12][0]
    pklen = ske[3]
    ecdh = ske[:4 + pklen]
    sig_alg = struct.unpack("!H", ske[4 + pklen:6 + pklen])[0]
    siglen = struct.unpack("!H", ske[6 + pklen:8 + pklen])[0]
    sig = ske[8 + pklen:8 + pklen + siglen]
    rnd_c = ch_msg[6:38]
    sh_msg = b"\x02" + struct.pack("!I", len(sh))[1:] + sh

    print("签名 %d 字节，sigalg=0x%04x，ECDH 组=0x%04x" % (siglen, sig_alg, struct.unpack("!H", ske[1:3])[0]))
    on_disk = subprocess.run(["openssl", "x509", "-in", BASE + "/PKI/CERT/f7679b33352bd0d0e150e8594606c01f.crt",
                              "-noout", "-fingerprint", "-sha256"], capture_output=True).stdout.decode().strip()
    flight_fp = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
                               input=leaf, capture_output=True).stdout.decode().strip()
    print("磁盘证书:", on_disk)
    print("飞行证书:", flight_fp)
    print("是否同一张:", on_disk.split("=")[1] == flight_fp.split("=")[1])

    inputs = {
        "randoms+ECDHParams": rnd_c + rnd_s + ecdh,
        "CH+SH+ECDHParams": ch_msg + sh_msg + ecdh,
        "randoms+exts+ECDHParams": rnd_c + rnd_s + sh[p + 5:p + 5 + exts_len] + ecdh,
        "仅 ECDHParams": ecdh,
    }

    candidates = sorted(glob.glob(BASE + "/PKI/KEY/*.key")) + sorted(glob.glob(BASE + "/PKI/ROOT/*.key")) \
        + sorted(glob.glob(BASE + "/PKI/OCSP/*.key")) + sorted(glob.glob(BASE + "/PKI/TIMSTAMP/*.key"))
    print("\n候选私钥 %d 个，开始逐个尝试：" % len(candidates))
    hits = 0
    for kp in candidates:
        got = pub_from_key(kp)
        if not got:
            continue
        n, e = got
        if (n.bit_length() + 7) // 8 != siglen:
            continue
        em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(siglen, "big")
        pkcs1 = em[:2] == b"\x00\x01"
        if not pkcs1:
            continue
        hits += 1
        name = os.path.basename(kp)
        print("  [PKCS#1 匹配] %s (e=%d)" % (name, e))
        for iname, data in inputs.items():
            for md in ("sha256", "sha384", "sha512", "sha1"):
                di = digest_info(md, hashlib.new(md, data).digest())
                if em.endswith(di):
                    print("      -> 待签数据=%s 哈希=%s  ✅ 完全匹配" % (iname, md))
    if hits == 0:
        print("  没有任何候选私钥能解出 PKCS#1 v1.5 结构 —— 签名不是这些 RSA 私钥产生的")


if __name__ == "__main__":
    main()
