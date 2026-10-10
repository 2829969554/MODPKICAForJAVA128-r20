# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 备份并追加 ikev2-cert 连接（IKE 层证书认证，Windows Machine Certificate 模式）
script = '''
cp /etc/swanctl/swanctl.conf /etc/swanctl/swanctl.conf.bak.$(date +%s)
cat >> /etc/swanctl/swanctl.conf <<'EOF'

    ikev2-cert {
        version = 2
        send_cert = always
        pools = vpnpool
        proposals = aes256-sha256-modp1024, aes256-sha1-modp1024, aes256-sha384-modp1024, aes128-sha256-modp1024, aes128-sha1-modp1024, aes128-sha384-modp1024, aes192-sha256-modp1024, aes192-sha1-modp1024, aes192-sha384-modp1024, 3des-sha256-modp1024, 3des-sha1-modp1024, 3des-sha384-modp1024, aes256gcm16-prfsha256-modp1024, aes256gcm16-prfsha1-modp1024, aes256gcm16-prfsha384-modp1024, aes128gcm16-prfsha256-modp1024, aes128gcm16-prfsha1-modp1024, aes128gcm16-prfsha384-modp1024, aes256-sha256-ecp256, aes256-sha256-modp2048, aes128-sha256-ecp256, aes128-sha256-modp2048
        local {
            auth = pubkey
            certs = f7679b33352bd0d0e150e8594606c01f.crt
            id = vpn.local
        }
        remote {
            auth = pubkey
            cacerts = 7712d9352e6038ce78e57e3f572cec74.crt
            id = %any
        }
        children {
            ikev2-cert {
                remote_ts = 0.0.0.0/0
            }
        }
    }
}
'''
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_conf_add.txt','w',encoding='utf-8') as f:
    f.write(run('cp /etc/swanctl/swanctl.conf /etc/swanctl/swanctl.conf.bak.$$ ; cat >> /etc/swanctl/swanctl.conf <<\'EOF\'\n\n    ikev2-cert {\n        version = 2\n        send_cert = always\n        pools = vpnpool\n        proposals = aes256-sha256-modp1024, aes256-sha1-modp1024, aes256-sha384-modp1024, aes128-sha256-modp1024, aes128-sha1-modp1024, aes128-sha384-modp1024, aes192-sha256-modp1024, aes192-sha1-modp1024, aes192-sha384-modp1024, 3des-sha256-modp1024, 3des-sha1-modp1024, 3des-sha384-modp1024, aes256gcm16-prfsha256-modp1024, aes256gcm16-prfsha1-modp1024, aes256gcm16-prfsha384-modp1024, aes128gcm16-prfsha256-modp1024, aes128gcm16-prfsha1-modp1024, aes128gcm16-prfsha384-modp1024, aes256-sha256-ecp256, aes256-sha256-modp2048, aes128-sha256-ecp256, aes128-sha256-modp2048\n        local {\n            auth = pubkey\n            certs = f7679b33352bd0d0e150e8594606c01f.crt\n            id = vpn.local\n        }\n        remote {\n            auth = pubkey\n            cacerts = 7712d9352e6038ce78e57e3f572cec74.crt\n            id = %any\n        }\n        children {\n            ikev2-cert {\n                remote_ts = 0.0.0.0/0\n            }\n        }\n    }\n}\nEOF\n'))
    f.write('\n=== 验证语法 ===\n')
    f.write(run('swanctl --load-all 2>&1 | grep -v "failed to load" | head -20; echo RC=$?'))
    f.write('\n=== 列出连接 ===\n')
    f.write(run('swanctl --list-conns 2>&1 | grep -E "^ikev2|auth|certs|cacerts" | head -30'))
cli.close(); print('DONE')
