# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_logging.txt','w',encoding='utf-8') as f:
    f.write('=== 当前日志配置 ===\n')
    f.write(run('ls -la /etc/strongswan.d/ 2>&1; cat /etc/strongswan.d/charon-logging.conf 2>&1 | head -40'))
    f.write('\n=== 写入详细日志配置 ===\n')
    f.write(run("cat > /etc/strongswan.d/charon-logging.conf <<'EOF'\ncharon {\n    filelog {\n        /var/log/charon.log {\n            time_format = %b %e %T\n            ike_name = yes\n            append = no\n            default = 3\n            flush_line = yes\n        }\n        stderr {\n            ike_name = yes\n            default = 3\n        }\n    }\n}\nEOF\n"))
    f.write(run('echo WRITTEN; cat /etc/strongswan.d/charon-logging.conf'))
    f.write('\n=== 重启 strongswan ===\n')
    f.write(run('systemctl restart strongswan 2>&1; sleep 2; systemctl is-active strongswan'))
    f.write('\n=== 加载连接 ===\n')
    f.write(run('swanctl --load-all 2>&1 | grep -vE "failed to load|plugin" | head -10'))
cli.close(); print('DONE')
