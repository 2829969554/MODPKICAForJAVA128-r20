# -*- coding: utf-8 -*-
"""改 eapol_test.c 开 MSG_DEBUG 重编译并运行。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=300):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 当前 debug 设置 ===")
print(run("grep -n 'wpa_debug_level' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c | head -5"))
print("=== 改为 MSG_DEBUG ===")
print(run("sed -i 's/wpa_debug_level = MSG_INFO;/wpa_debug_level = MSG_DEBUG;/' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c && grep -n 'wpa_debug_level = MSG' /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test.c"))
print("=== 重编译 ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && make eapol_test 2>&1 | tail -3 && cp eapol_test /usr/local/bin/"))
cli.close()
