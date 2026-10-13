# -*- coding: utf-8 -*-
"""核对根证书（带异常打印）。"""
import paramiko, sys, io, traceback
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
try:
    cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
    def run(cmd, t=60):
        i,o,e = cli.exec_command(cmd, timeout=t)
        return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
    print("=== 网关 root.crt ===")
    print(run("openssl x509 -in /tmp/certs/root.crt -noout -subject -issuer -serial -fingerprint -sha256 2>&1"))
    print("=== 本地根 7712d935（sftp 上传到网关）===")
    sftp = cli.open_sftp()
    sftp.put(r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\ROOT\7712d9352e6038ce78e57e3f572cec74.crt", "/tmp/certs/root_local.crt")
    print(run("openssl x509 -in /tmp/certs/root_local.crt -noout -subject -issuer -serial -fingerprint -sha256 2>&1"))
    print("=== 服务端证书校验 ===")
    sftp.put(r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\CERT\f7679b33352bd0d0e150e8594606c01f.crt", "/tmp/certs/server_f7679b.crt")
    print(run("openssl verify -CAfile /tmp/certs/root_local.crt /tmp/certs/server_f7679b.crt 2>&1"))
    print("=== 服务端证书 EKU/SAN ===")
    print(run("openssl x509 -in /tmp/certs/server_f7679b.crt -noout -text 2>&1 | grep -A3 'Extended Key Usage\\|Subject Alternative Name'"))
    cli.close()
except Exception:
    traceback.print_exc()
