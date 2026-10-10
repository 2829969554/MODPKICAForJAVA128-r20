# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=25):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_swanctl.txt','w',encoding='utf-8') as f:
    f.write('=== swanctl.conf ===\n')
    f.write(run('cat /etc/swanctl/swanctl.conf 2>/dev/null; echo ---; cat /etc/strongswan.conf 2>/dev/null'))
    f.write('\n=== /etc/swanctl/x509 ===\n')
    f.write(run('ls -la /etc/swanctl/x509/ 2>/dev/null; echo ---; ls -la /etc/swanctl/rsa/ 2>/dev/null; echo ---; ls -la /etc/swanctl/ecdsa/ 2>/dev/null; echo ---; ls -la /etc/swanctl/private/ 2>/dev/null'))
    f.write('\n=== 证书 CN 对应 ===\n')
    f.write(run('for c in /etc/swanctl/x509/*.pem; do echo "== $c"; openssl x509 -in "$c" -noout -subject -serial -ext subjectAltName 2>/dev/null | head -8; done'))
cli.close(); print('DONE')
