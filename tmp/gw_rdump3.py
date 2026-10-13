# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
sftp = cli.open_sftp()
sftp.get('/tmp/rdump_x.txt', r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\rdump_x.txt')
sftp.close(); cli.close()
print("OK")
