# -*- coding: utf-8 -*-
"""上传客户端证书到网关，配置并运行 eapol_test 直连 RADIUS EAP-TLS。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
sftp = cli.open_sftp()
for name, src in [("client.crt", r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\CERT\a66de5fea3df44c8f8687f31d75384d.crt"),
                  ("client.key", r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\KEY\a66de5fea3df44c8f8687f31d75384d.key"),
                  ("root.crt",   r"C:\Users\28299\Desktop\modpkica4JAVA\PKI\ROOT\7712d9352e6038ce78e57e3f572cec74.crt")]:
    try:
        sftp.put(src, f"/tmp/certs/{name}")
        print(f"上传 {name} OK")
    except Exception as ex:
        print(f"上传 {name} 失败: {ex}")
sftp.close()

def run(cmd, t=120):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 生成 eapol_test 配置 ===")
conf = """network={
	key_mgmt=WPA-EAP
	eap=TLS
	identity="admin666"
	ca_cert="/tmp/certs/root.crt"
	client_cert="/tmp/certs/client.crt"
	private_key="/tmp/certs/client.key"
	private_key_passwd=""
	eapol_flags=0
}
"""
print(run("mkdir -p /tmp/certs && cat > /tmp/eap-tls.conf <<'EOF'\n" + conf + "EOF\ncat /tmp/eap-tls.conf"))
print("=== 运行 eapol_test 直连 RADIUS ===")
print(run("cd /tmp && timeout 40 eapol_test -c /tmp/eap-tls.conf -a 10.255.228.55 -p 1812 -s mytestkey -t 30 2>&1 | tail -30"))
cli.close()
