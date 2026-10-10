# -*- coding: utf-8 -*-
import subprocess, io, sys, os, tempfile
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
BASE = r'C:\Users\28299\Desktop\modpkica4JAVA\PKI'
TMP = r'C:\Users\28299\Desktop\modpkica4JAVA\tmp'
ROOT_CRT = os.path.join(BASE, 'ROOT', '7712d9352e6038ce78e57e3f572cec74.crt')
ROOT_KEY = os.path.join(BASE, 'KEY', '7712d9352e6038ce78e57e3f572cec74.key')
SRV_KEY = os.path.join(TMP, 'srv_clean.key')
SRV_CSR = os.path.join(TMP, 'srv_clean.csr')
SRV_CRT = os.path.join(TMP, 'srv_clean.crt')
EXT = os.path.join(TMP, 'srv_clean.ext')

ext_content = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:vpn.local,IP:10.255.228.225,IP:127.0.0.1
"""
with open(EXT, 'w', encoding='utf-8') as f:
    f.write(ext_content)

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.returncode, (r.stdout or '') + (r.stderr or '')

rc, out = sh(f'openssl req -new -newkey rsa:2048 -keyout "{SRV_KEY}" -out "{SRV_CSR}" -subj "/C=CN/L=newer york/O=China IT Boys/OU=IT Clubs/CN=vpn.local" -nodes -sha256 2>&1')
print('REQ:', rc, out.strip()[-200:])
rc, out = sh(f'openssl x509 -req -in "{SRV_CSR}" -CA "{ROOT_CRT}" -CAkey "{ROOT_KEY}" -CAcreateserial -out "{SRV_CRT}" -days 365 -sha256 -extfile "{EXT}" 2>&1')
print('SIGN:', rc, out.strip()[-200:])
rc, out = sh(f'openssl verify -CAfile "{ROOT_CRT}" "{SRV_CRT}" 2>&1')
print('VERIFY:', rc, out.strip())
rc, out = sh(f'openssl x509 -in "{SRV_CRT}" -noout -text 2>&1')
print('DETAIL:', out.strip()[-1200:])
