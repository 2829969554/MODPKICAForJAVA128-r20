# -*- coding: utf-8 -*-
# 停止网关抓包，拉回 pcap 到本地
import paramiko, os

GW = "10.255.228.225"
USER = "root"
PWD = "root"
LOCAL = r"C:\Users\28299\Desktop\modpkica4JAVA\tmp\radius_win11.pcap"

def run(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(GW, username=USER, password=PWD, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    c.close()
    return out, err

out, err = run("pkill -f 'tcpdump.*1812'; sleep 1; ls -l /tmp/radius_win11.pcap; echo DONE")
print("STOP:", out.strip(), err.strip())

# 拉回文件
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(GW, username=USER, password=PWD, timeout=10)
sftp = c.open_sftp()
sftp.get("/tmp/radius_win11.pcap", LOCAL)
sftp.close()
c.close()
print("DOWNLOADED:", LOCAL, os.path.getsize(LOCAL), "bytes")
