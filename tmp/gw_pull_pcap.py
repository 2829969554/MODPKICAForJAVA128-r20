# -*- coding: utf-8 -*-
"""拉取网关 pcap 回本地并统计 RADIUS 响应内容。"""
import paramiko, traceback
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
    sftp = cli.open_sftp()
    for name in ["ios_radius_r28.pcap", "ios_ike_r28.pcap"]:
        try:
            sftp.get(f"/tmp/{name}", rf"C:\Users\28299\Desktop\modpkica4JAVA\tmp\{name}")
            print(f"拉回 {name} OK")
        except Exception as ex:
            print(f"拉回 {name} 失败: {ex}")
    sftp.close()
    cli.close()
except Exception:
    traceback.print_exc()
