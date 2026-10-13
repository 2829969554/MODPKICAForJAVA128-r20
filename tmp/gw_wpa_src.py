# -*- coding: utf-8 -*-
"""查 wpa_supplicant eap_tls.c 对 TLS Start 的校验。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== eap_tls.c Start 处理 ===")
print(run("grep -n 'FLAGS_START\\|eap_tls_state == START\\|case START' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls.c | head -20"))
print()
print(run("sed -n '/static struct wpabuf \\* eap_tls_process/,/^}/p' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls.c | head -120"))
cli.close()
