# -*- coding: utf-8 -*-
"""直接抓 eap_tls_common.c 相关函数。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 函数位置 ===")
print(run("grep -n 'eap_peer_tls_process_init\\|eap_peer_tls_process_helper' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls_common.c"))
print("=== process_init 正文 ===")
print(run("awk '/^const u8 \\* eap_peer_tls_process_init/{f=1} f{print; if(/^}/) exit}' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls_common.c | head -90"))
cli.close()
