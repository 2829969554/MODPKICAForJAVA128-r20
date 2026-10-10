# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# SFTP 上传配置块
sftp = cli.open_sftp()
sftp.put(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\ikev2cert_block.conf', '/tmp/ikev2cert_block.conf')
sftp.close()

with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_cert_conn.txt','w',encoding='utf-8') as f:
    f.write('=== 备份 ===\n')
    f.write(run('cp /etc/swanctl/swanctl.conf /etc/swanctl/swanctl.conf.bak2'))
    f.write('\n=== 移除旧的 ikev2-cert 块（如有）并追加新块 ===\n')
    # 删除已存在的 ikev2-cert 块（防止重复）
    f.write(run("python3 - <<'PY'\np='/etc/swanctl/swanctl.conf'\ns=open(p,encoding='utf-8').read()\nimport re\ns=re.sub(r'\\n    ikev2-cert \\{.*?\\n    \\}', '', s, flags=re.S)\nopen(p,'w',encoding='utf-8').write(s)\nPY"))
    f.write(run("sed -i '/^}/d' /etc/swanctl/swanctl.conf"))
    f.write(run("cat /tmp/ikev2cert_block.conf >> /etc/swanctl/swanctl.conf"))
    f.write('\n=== 语法检查+加载 ===\n')
    f.write(run('swanctl --load-all 2>&1 | grep -vE "failed to load|plugin" | head -15; echo RC=$?'))
    f.write('\n=== 连接列表 ===\n')
    f.write(run('swanctl --list-conns 2>&1 | grep -E "^ikev2|auth|certs|cacerts|id:" | head -30'))
cli.close(); print('DONE')
