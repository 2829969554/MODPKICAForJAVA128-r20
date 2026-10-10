# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_restart.txt','w',encoding='utf-8') as f:
    f.write('=== 服务名 ===\n')
    f.write(run('systemctl list-units --type=service | grep -i strongswan; systemctl list-units --type=service | grep -i strong; ls /etc/init.d/ | grep -i strong'))
    f.write('\n=== 重启 ===\n')
    f.write(run('systemctl restart strongswan 2>&1 || systemctl restart strongswan-starter 2>&1 || service strongswan restart 2>&1; sleep 3; systemctl --no-pager status strongswan 2>&1 | head -8; systemctl --no-pager status strongswan-starter 2>&1 | head -8'))
    f.write('\n=== 加载配置 ===\n')
    f.write(run('swanctl --load-all 2>&1 | head -20; echo RC=$?'))
    f.write('\n=== 当前加载证书 ===\n')
    f.write(run('swanctl --list-conns 2>&1 | head -40'))
cli.close(); print('DONE')
