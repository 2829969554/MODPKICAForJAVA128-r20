# -*- coding: utf-8 -*-
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

HOST, PORT = "10.255.228.225", 22
USER, PW = "root", "root"

cmds = [
    ("主机名/版本", "hostname; uname -a | head -1"),
    ("strongSwan 版本", "ipsec version 2>/dev/null | head -2; strongswan version 2>/dev/null | head -2"),
    ("swanctl.conf", "cat /etc/swanctl/swanctl.conf 2>/dev/null | head -120"),
    ("eap-radius.conf", "cat /etc/strongswan.d/charon/eap-radius.conf 2>/dev/null"),
    ("strongswan.d 主配置(插件)", "grep -rn 'eap-tls\\|eap-radius\\|eap-mschapv2' /etc/strongswan.d/ 2>/dev/null | head -20"),
    ("ipsec statusall", "ipsec statusall 2>/dev/null | head -40"),
    ("IPSec 最近错误日志", "journalctl -u strongswan -u strongswan-starter --no-pager -n 120 2>/dev/null | tail -80"),
]

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(HOST, PORT, USER, PW, timeout=10, auth_timeout=10, banner_timeout=10, allow_agent=False, look_for_keys=False)
for name, cmd in cmds:
    print("\n" + "=" * 20 + " " + name + " " + "=" * 20)
    stdin, stdout, stderr = cli.exec_command(cmd, timeout=15)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    if out.strip():
        print(out)
    if err.strip():
        print("[stderr] " + err)
cli.close()
