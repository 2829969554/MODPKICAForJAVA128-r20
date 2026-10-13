# -*- coding: utf-8 -*-
"""查 eap_tls_common.c 的 process_init 完整校验。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== eap_peer_tls_process_init 完整代码 ===")
print(run("sed -n '/const u8 \\* eap_peer_tls_process_init/,/^}/p' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls_common.c"))
print("=== eap_peer_tls_process_helper 开头（res<0 判定） ===")
print(run("sed -n '/int eap_peer_tls_process_helper/,/tls_connection_established/p' /tmp/wpa_supplicant-2.10/src/eap_peer/eap_tls_common.c | head -60"))
cli.close()
