# -*- coding: utf-8 -*-
"""下载 wpa_supplicant 源码并编译 eapol_test。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=240):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 下载源码 ===")
print(run("cd /tmp && (ls wpa_supplicant-2.10.tar.gz >/dev/null 2>&1 || wget -q --timeout=60 https://w1.fi/releases/wpa_supplicant-2.10.tar.gz) ; ls -la wpa_supplicant-2.10.tar.gz 2>/dev/null | awk '{print $5, $9}'"))
cli.close()
