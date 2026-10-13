# -*- coding: utf-8 -*-
import paramiko, traceback
out = []
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
    def run(cmd, t=60):
        i,o,e = cli.exec_command(cmd, timeout=t)
        return (o.read() + e.read()).decode('utf-8','replace')
    out.append("=== /tmp/certs 目录 ===\n" + run("ls -la /tmp/certs/"))
    out.append("=== 网关 root.crt 指纹 ===\n" + run("openssl x509 -in /tmp/certs/root.crt -noout -serial -fingerprint -sha256 2>&1"))
    out.append("=== eap-tls.conf ===\n" + run("cat /tmp/eap-tls.conf"))
    cli.close()
except Exception:
    out.append("EXC: " + traceback.format_exc())
with open(r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_check4_result.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out))
