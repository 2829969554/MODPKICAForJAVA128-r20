# -*- coding: utf-8 -*-
"""网关从源码编译 eapol_test（wpa_supplicant 2.10）。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=300):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 装构建依赖 ===")
print(run("apt-get install -y build-essential libssl-dev libnl-3-dev libnl-genl-3-dev pkg-config 2>&1 | tail -3"))
print("=== 下载源码 ===")
print(run("cd /tmp && (ls wpa_supplicant-2.10.tar.gz 2>/dev/null || wget -q https://w1.fi/releases/wpa_supplicant-2.10.tar.gz) && tar xzf wpa_supplicant-2.10.tar.gz 2>/dev/null; ls -d /tmp/wpa_supplicant-2.10 2>/dev/null"))
print("=== 配置并编译 eapol_test ===")
print(run("cd /tmp/wpa_supplicant-2.10/wpa_supplicant && cp defconfig .config && sed -i 's/#CONFIG_EAP_TLS=y/CONFIG_EAP_TLS=y/; s/#CONFIG_EAP_PEAP=y/CONFIG_EAP_PEAP=y/; s/#CONFIG_EAP_MSCHAPV2=y/CONFIG_EAP_MSCHAPV2=y/' .config && echo 'CONFIG_DRIVER_NONE=y' >> .config && echo 'CONFIG_EAPOL_TEST=y' >> .config && make eapol_test 2>&1 | tail -6"))
print("=== 结果 ===")
print(run("ls -la /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test 2>/dev/null && cp /tmp/wpa_supplicant-2.10/wpa_supplicant/eapol_test /usr/local/bin/ && eapol_test --help 2>&1 | head -3"))
cli.close()
