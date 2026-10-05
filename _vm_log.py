# -*- coding: utf-8 -*-
"""查看 strongSwan 网关日志，定位原生 VPN 失败阶段。"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.1.42", username="wxg", password="wanggang", timeout=15)

def sudo_run(cmd, timeout=40):
    stdin, stdout, stderr = ssh.exec_command(f"sudo -S bash -c '{cmd}'", timeout=timeout)
    stdin.write("wanggang\n"); stdin.flush()
    out = stdout.read().decode("utf-8","replace"); err = stderr.read().decode("utf-8","replace")
    rc = stdout.channel.recv_exit_status()
    print(f"$ {cmd}\n  rc={rc}")
    if out.strip(): print("  OUT:", out.strip()[:4000])
    if err.strip() and 'password' not in err[:40]: print("  ERR:", err.strip()[:1000])
    return rc

# 最近 40 行 strongSwan 日志（含时间戳）
sudo_run("journalctl -u strongswan --no-pager -n 40 | tail -40")
# 查看所有活动连接与会话
sudo_run("swanctl --list-sas")
# 当前加载的连接配置
sudo_run("swanctl --list-conns")
ssh.close()
print("完成")
