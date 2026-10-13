# -*- coding: utf-8 -*-
"""SSH 到 strongSwan 网关抓 EAP-RADIUS / charon 日志，分析 iOS 重传风暴期间网关转发行为。"""
import paramiko, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

HOST = "10.255.228.225"

def run(host, user, pw, cmds):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=pw, timeout=8)
    for cmd in cmds:
        print("=" * 20, "CMD:", cmd, "=" * 20)
        stdin, stdout, stderr = c.exec_command(cmd, timeout=25)
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        print(out)
        if err.strip():
            print("--- stderr ---")
            print(err)
    c.close()

cmds = [
    # 最近 40 分钟 strongSwan 主日志（含 eap-radius 转发、EAP 消息、IKE 状态）
    "journalctl -u strongswan --since '40 minutes ago' --no-pager 2>/dev/null | tail -150",
    # 连接状态与策略
    "ipsec statusall 2>/dev/null | head -60",
    # 加载的 eap-radius 配置
    "grep -rn 'eap-radius' /etc/strongswan.d/ 2>/dev/null; echo '---'; cat /etc/strongswan.d/charon/eap-radius.conf 2>/dev/null",
]

try:
    run(HOST, "root", "root", cmds)
except Exception as e:
    print("root/root 失败:", e)
    try:
        run(HOST, "wxg", "wanggang", cmds)
    except Exception as e2:
        print("wxg/wanggang 也失败:", e2)
