#!/bin/bash
set -e
cd /tmp
if [ ! -f ss.tar.bz2 ]; then
  wget -q https://mirrors.tuna.tsinghua.edu.cn/debian/pool/main/s/strongswan/strongswan_6.0.1.orig.tar.bz2 -O ss.tar.bz2
fi
if [ ! -d strongswan-6.0.1 ]; then
  tar xjf ss.tar.bz2
fi
find strongswan-6.0.1/src -name '*eap_ikev2*' -o -name '*eap_manager*' | head -20
echo "===DONE==="
