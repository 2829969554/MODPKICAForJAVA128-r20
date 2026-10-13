# -*- coding: utf-8 -*-
"""找 eapol_test 二进制位置；若无则从源码或其它包补。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 查找 eapol_test ===")
print(run("find / -name 'eapol_test' -type f 2>/dev/null | head -5; dpkg -L wpasupplicant | grep -i eapol | head -5"))
print("=== wpa_supplicant 帮助（EAP-TLS 相关） ===")
print(run("wpa_supplicant -h 2>&1 | head -3"))
cli.close()
