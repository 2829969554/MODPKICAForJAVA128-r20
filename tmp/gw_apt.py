# -*- coding: utf-8 -*-
"""分步：等 apt 锁并安装依赖。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=240):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 等待 apt 锁并安装 ===")
print(run("while fuser /var/lib/dpkg/lock-frontend 2>/dev/null; do sleep 2; done; DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev libnl-3-dev libnl-genl-3-dev pkg-config 2>&1 | tail -5"))
print("=== 确认 gcc ===")
print(run("gcc --version | head -1"))
cli.close()
