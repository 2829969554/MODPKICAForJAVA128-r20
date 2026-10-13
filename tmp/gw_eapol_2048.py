# -*- coding: utf-8 -*-
"""换 RSA-2048 客户端证书重跑 eapol_test。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=120):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

sftp = cli.open_sftp()
for name, src in [("client.crt", r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\CERT\584ad9b373187743d26051e32441ebd2.crt"),
                  ("client.key", r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\KEY\584ad9b373187743d26051e32441ebd2.key")]:
    try:
        sftp.put(src, f"/tmp/certs/{name}")
        print(f"上传 {name} OK")
    except Exception as ex:
        print(f"上传 {name} 失败: {ex}")
sftp.close()
print(run("ls -la /tmp/certs/client.*"))
print("=== 证书信息 ===")
print(run("openssl x509 -in /tmp/certs/client.crt -noout -subject -issuer -serial -dates -ext extendedKeyUsage 2>&1"))
print("=== 私钥类型 ===")
print(run("openssl pkey -in /tmp/certs/client.key -noout -text 2>/dev/null | head -3"))
out = run("cd /tmp && timeout 60 eapol_test -c /tmp/eap-tls.conf -a 10.255.228.55 -p 1812 -s mytestkey -t 45 debug 2>&1", t=90)
for line in out.splitlines():
    low = line.lower()
    if any(k in low for k in ['eap-tls', 'ssl:', 'tls', 'nak', 'method', 'flags', 'certificate', 'fail', 'error', 'success', 'phase', 'received eap', 'server hello', 'client hello']):
        print(line)
cli.close()
