# -*- coding: utf-8 -*-
"""查 eapol_test.c 行数与 main 调试设置。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 行数 ===")
print(run("wc -l /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c"))
print("=== wpa_debug 上下文 ===")
print(run("grep -n -B3 -A5 'wpa_debug_level' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c"))
cli.close()
