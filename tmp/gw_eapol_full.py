# -*- coding: utf-8 -*-
"""重跑 eapol_test，完整输出写文件（不过滤），重点看证书验证。"""
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=120):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return (o.read() + e.read()).decode('utf-8','replace')
out = run("cd /tmp && timeout 60 eapol_test -c /tmp/eap-tls.conf -a 10.255.228.55 -p 1812 -s mytestkey -t 45 debug 2>&1", t=90)
with open(r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\eapol_full_r28.txt", "w", encoding="utf-8") as f:
    f.write(out)
cli.close()
print("written, lines=", len(out.splitlines()))
