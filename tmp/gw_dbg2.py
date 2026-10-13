# -*- coding: utf-8 -*-
"""看 eapol_test.c main 的 debug 设置上下文。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 1180-1200 ===")
print(run("sed -n '1180,1200p' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c"))
print("=== 1310-1330 ===")
print(run("sed -n '1310,1330p' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c"))
cli.close()
