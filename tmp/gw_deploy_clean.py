# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 备份原文件
run('cp /etc/swanctl/x509/f7679b33352bd0d0e150e8594606c01f.crt /etc/swanctl/x509/f7679b.orig.crt')
run('cp /etc/swanctl/private/f7679b33352bd0d0e150e8594606c01f.key /etc/swanctl/private/f7679b.orig.key')

sftp = cli.open_sftp()
sftp.put(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\srv_clean.crt', '/etc/swanctl/x509/f7679b33352bd0d0e150e8594606c01f.crt')
sftp.put(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\srv_clean.key', '/etc/swanctl/private/f7679b33352bd0d0e150e8594606c01f.key')
sftp.close()

with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_deploy.txt','w',encoding='utf-8') as f:
    f.write('=== 校验新证书公钥与私钥匹配 ===\n')
    f.write(run('a=$(openssl x509 -in /etc/swanctl/x509/f7679b33352bd0d0e150e8594606c01f.crt -noout -pubkey | openssl md5); b=$(openssl pkey -in /etc/swanctl/private/f7679b33352bd0d0e150e8594606c01f.key -pubout | openssl md5); echo "cert=$a key=$b"; if [ "$a" = "$b" ]; then echo MATCH; else echo MISMATCH; fi'))
    f.write('\n=== 新证书主题 ===\n')
    f.write(run('openssl x509 -in /etc/swanctl/x509/f7679b33352bd0d0e150e8594606c01f.crt -noout -subject -ext extendedKeyUsage,subjectAltName 2>&1'))
    f.write('\n=== 重启 ===\n')
    f.write(run('systemctl restart strongswan 2>&1; sleep 2; systemctl is-active strongswan'))
    f.write(run('swanctl --load-all 2>&1 | grep -E "loaded connection|successfully loaded" | head -5'))
cli.close(); print('DONE')
