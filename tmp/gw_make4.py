# -*- coding: utf-8 -*-
"""装 libnl-route-3-dev 并最终编译 eapol_test。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=300):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 装 libnl-route-3-dev ===")
print(run("while fuser /var/lib/dpkg/lock-frontend 2>/dev/null; do sleep 2; done; DEBIAN_FRONTEND=noninteractive apt-get install -y libnl-route-3-dev 2>&1 | tail -3"))
print("=== 编译 ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && make eapol_test 2>&1 | tail -4"))
print("=== 安装确认 ===")
print(run("ls -la /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test 2>/dev/null && cp /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test /usr/local/bin/ && eapol_test --help 2>&1 | head -4"))
cli.close()
