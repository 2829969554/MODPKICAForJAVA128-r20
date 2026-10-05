# -*- coding: utf-8 -*-
"""临时把根证书 CERTS.txt 登记算法 RSA-PSS→RSA，签发 PKCS#1 证书后恢复。"""
import io, sys, shutil, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

CERTS = r"C:\Users\28299\Desktop\mygit\modpkicaforjava\PKI\CERTS.txt"
ROOT_SERIAL = "6cfbd3ad26f760570e04dd10a8f42822"

# 备份
bak = CERTS + ".bak_vpn"
shutil.copy2(CERTS, bak)
print("备份:", bak)

with open(CERTS, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

new_lines = []
for ln in lines:
    s = ln.rstrip("\n")
    if s.startswith(ROOT_SERIAL):
        # 行格式: serial R V 0 日期 issuer RSA-PSS → 只把算法列 RSA-PSS 改 RSA
        parts = s.split()
        if len(parts) >= 7 and parts[-1].upper() == "RSA-PSS":
            parts[-1] = "RSA"
            s = " ".join(parts)
            print("根行已临时改为:", s)
    new_lines.append(s + "\n")

with open(CERTS, "w", encoding="utf-8", newline="") as f:
    f.writelines(new_lines)
print("CERTS.txt 已更新")
