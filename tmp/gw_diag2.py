# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)

def run(cmd, t=25):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print('=== 残留 tcpdump 进程详情 ===')
print(run('ps -ef | grep tcpdump | grep -v grep'))
print('=== 手动测试 tcpdump 写文件（5秒） ===')
print(run('rm -f /tmp/t.pcap; timeout 5 tcpdump -i any -s 0 -w /tmp/t.pcap "udp" 2>&1 | tail -3; ls -la /tmp/t.pcap 2>/dev/null || echo TEST_FAIL'))
print('=== journalctl 最近 strongswan 记录（含时间戳） ===')
print(run('journalctl -u strongswan --no-pager -n 40 2>/dev/null | tail -40'))
cli.close()
