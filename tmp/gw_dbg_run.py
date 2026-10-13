# -*- coding: utf-8 -*-
"""debug 模式重跑 eapol_test，完整输出。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=120):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

out = run("cd /tmp && timeout 40 eapol_test -c /tmp/eap-tls.conf -a 10.255.228.55 -p 1812 -s mytestkey -t 30 debug 2>&1", t=60)
# 打印关键调试行
print("=== 与 TLS/NAK/方法相关行 ===")
for line in out.splitlines():
    low = line.lower()
    if any(k in low for k in ['eap-tls', 'eap_tls', 'ssl:', 'nak', 'method', 'tls', 'client hello', 'flags', 'phase', 'eap type', 'allowed', 'ignore', 'error', 'fail']):
        print(line)
cli.close()
