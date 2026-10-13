# -*- coding: utf-8 -*-
"""查 strongSwan 版本/特性配置，确认 IKE_AUTH[R] 载荷类型 0x2e 的来源。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== strongSwan 版本 ===")
print(run("ipsec version 2>/dev/null; strongswan version 2>/dev/null | head -5"))
print("=== charon 插件/特性 (ipsec.conf 相关) ===")
print(run("cat /etc/strongswan.conf 2>/dev/null | head -40"))
print("=== 查 Intermediate Exchange / 新载荷相关配置 ===")
print(run("grep -ri 'intermediate\\|exch_max\\|send_cert\\|eap-radius\\|ikesa\\|rekey' /etc/strongswan* /etc/ipsec.conf /etc/strongswan.d 2>/dev/null | head -30"))
print("=== journalctl strongswan 最近 20 行 ===")
print(run("journalctl -u strongswan --no-pager -n 20 2>/dev/null | tail -20"))
cli.close()
