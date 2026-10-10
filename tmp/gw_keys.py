# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_keys.txt','w',encoding='utf-8') as f:
    f.write('=== 证书公钥 ===\n')
    f.write(run('for c in f7679b33352bd0d0e150e8594606c01f b53080fef0b95fd6730fec18d55b6ac8; do echo "-- $c.crt"; openssl x509 -in /etc/swanctl/x509/$c.crt -noout -pubkey 2>&1 | openssl md5; done'))
    f.write('\n=== 私钥公钥 ===\n')
    f.write(run('for k in f7679b33352bd0d0e150e8594606c01f b53080fef0b95fd6730fec18d55b6ac8; do echo "-- $k.key"; openssl pkey -in /etc/swanctl/private/$k.key -pubout 2>&1 | openssl md5; done'))
    f.write('\n=== 私钥头部 ===\n')
    f.write(run('for k in f7679b33352bd0d0e150e8594606c01f b53080fef0b95fd6730fec18d55b6ac8; do echo "-- $k.key"; head -1 /etc/swanctl/private/$k.key; grep -c "BEGIN" /etc/swanctl/private/$k.key; done'))
cli.close(); print('DONE')
