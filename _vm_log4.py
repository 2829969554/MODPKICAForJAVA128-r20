# -*- coding: utf-8 -*-
"""查看 strongSwan 最近日志（最新 iPhone 尝试）。"""
import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("192.168.1.42", username="wxg", password="wanggang", timeout=15)

stdin, stdout, stderr = ssh.exec_command("sudo -S journalctl -u strongswan --no-pager -n 80", timeout=45)
stdin.write("wanggang\n"); stdin.flush()
out = stdout.read().decode("utf-8","replace")
rc = stdout.channel.recv_exit_status()
skip = re.compile(r'plugin|capabilities|loaded 0 RADIUS|HA config|forecast|multicast|appeared|disappeared|charon-systemd\[3|swanctl\[|archive|loaded certificate|loaded RSA|loaded IKE|unloaded|updated vici|pool vpnpool')
lines = [l for l in out.splitlines() if l.strip() and not skip.search(l)]
for l in lines[-50:]:
    print(l)
ssh.close()
print("完成")
