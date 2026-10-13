# -*- coding: utf-8 -*-
"""网关装 wpasupplicant（含 eapol_test），准备 EAP-TLS 直连测试。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== eapol_test 是否已有 ===")
print(run("which eapol_test; eapol_test --help 2>&1 | head -3"))
print("=== 安装 wpasupplicant（若没有） ===")
print(run("dpkg -l | grep wpasupplicant || (apt-get update -qq 2>&1 | tail -2; apt-get install -y wpasupplicant 2>&1 | tail -5)"))
print("=== 再次确认 ===")
print(run("which eapol_test && eapol_test --help 2>&1 | head -5"))
cli.close()
