#!/usr/bin/env bash
# ============================================================================
# MODPKICA × strongSwan 一键安装部署脚本（Debian 13 / strongSwan 6.x）
# ----------------------------------------------------------------------------
# 用法:
#   sudo bash install_strongswan.sh [RADIUS_SERVER] [RADIUS_SECRET] [网关ID]
#
# 参数（均可省略）:
#   $1 RADIUS_SERVER   Windows 主机 IP（Java RADIUS 所在） 默认 10.255.228.55
#   $2 RADIUS_SECRET   RADIUS 共享密钥（PKI/CONFIG.txt 的 RADIUSKEY） 默认 mytestkey
#   $3 网关ID          网关证书 CN/SAN（remote ID） 默认 vpn.local
#
# 证书部署（任选其一，脚本自动识别）:
#   A. 推荐：先把证书 scp 到服务器 /tmp：
#        scp PKI/CERT/{序列号}.crt  root@服务器:/tmp/gw.crt
#        scp PKI/KEY/{序列号}.key   root@服务器:/tmp/gw.key
#        scp PKI/ROOT/{序列号}.crt  root@服务器:/tmp/root.crt
#   B. 证书已手动放进 /etc/swanctl/x509/ 与 /etc/swanctl/private/（脚本自动选用第一对）
#
# 脚本自动完成: 安装 strongSwan 6.x -> 部署证书 -> 写 swanctl.conf /
#   eap-radius.conf -> 开启内核转发 -> 配置 NAT -> 启动并验证 swanctl --list-conns
# ============================================================================

set -u

RADIUS_SERVER="${1:-10.255.228.55}"
RADIUS_SECRET="${2:-mytestkey}"
GW_ID="${3:-vpn.local}"

POOL_ADDRS="10.10.0.0/24"
DNS1="223.5.5.5"
DNS2="8.8.8.8"

GW_CERT="gw.crt"        # /etc/swanctl/x509/gw.crt
GW_KEY="gw.key"         # /etc/swanctl/private/gw.key
ROOT_CERT="root.crt"    # /etc/swanctl/x509ca/root.crt

log()  { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!!]\033[0m $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; exit 1; }

# ---------- 0. root 检查 ----------
[ "$(id -u)" = "0" ] || fail "请用 root 或 sudo 运行: sudo bash $0 $*"

# ---------- 1. 安装 strongSwan ----------
log "安装 strongSwan (6.x) ..."
apt-get update -qq || warn "apt update 失败，继续尝试安装"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    strongswan strongswan-pki libcharon-extra-plugins \
    iptables iptables-persistent 2>&1 | tail -5 || fail "strongSwan 安装失败"

SWANVER=$(swanctl --version 2>/dev/null | tail -1)
log "strongSwan 版本: ${SWANVER:-未知}"

# ---------- 2. 准备目录 ----------
mkdir -p /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca
mkdir -p /etc/strongswan.d/charon

# ---------- 3. 部署证书 ----------
# 方式 A: /tmp/gw.crt + /tmp/gw.key + /tmp/root.crt
# 方式 B: /etc/swanctl 已有证书
SRC_CRT="/tmp/gw.crt"; SRC_KEY="/tmp/gw.key"; SRC_ROOT="/tmp/root.crt"

if [ -f "$SRC_CRT" ] && [ -f "$SRC_KEY" ] && [ -f "$SRC_ROOT" ]; then
    cp "$SRC_CRT"  "/etc/swanctl/x509/$GW_CERT"      || fail "拷贝网关证书失败"
    cp "$SRC_KEY"  "/etc/swanctl/private/$GW_KEY"    || fail "拷贝网关私钥失败"
    cp "$SRC_ROOT" "/etc/swanctl/x509ca/$ROOT_CERT"  || fail "拷贝根证书失败"
    log "证书已从 /tmp 部署: $GW_CERT / $GW_KEY / $ROOT_CERT"
elif ls /etc/swanctl/x509/*.crt >/dev/null 2>&1; then
    # 自动选用 x509 下第一张证书（需 private 有同名 .key）
    AUTO=$(ls /etc/swanctl/x509/*.crt 2>/dev/null | head -1)
    [ -f "$AUTO" ] || fail "未找到可用证书"
    BASENAME=$(basename "$AUTO" .crt)
    if [ -f "/etc/swanctl/private/$BASENAME.key" ]; then
        GW_CERT="$BASENAME.crt"; GW_KEY="$BASENAME.key"
        # 根证书: 优先 x509ca 里已有，否则尝试 /tmp/root.crt
        if ! ls /etc/swanctl/x509ca/*.crt >/dev/null 2>&1 && [ -f "$SRC_ROOT" ]; then
            cp "$SRC_ROOT" "/etc/swanctl/x509ca/$ROOT_CERT" || fail "拷贝根证书失败"
        fi
        log "复用已有证书: $GW_CERT / $GW_KEY"
    else
        fail "已发现 $AUTO 但缺少对应私钥 /etc/swanctl/private/$BASENAME.key"
    fi
else
    fail "未找到证书！请先执行: scp PKI/CERT/{序列号}.crt root@服务器:/tmp/gw.crt （连同 gw.key / root.crt）"
fi

chown root:root /etc/swanctl/x509/* /etc/swanctl/private/* /etc/swanctl/x509ca/* 2>/dev/null
chmod 600 /etc/swanctl/private/*.key
chmod 644 /etc/swanctl/x509/*.crt /etc/swanctl/x509ca/*.crt 2>/dev/null
log "证书权限已设置（私钥 600）"

# 自动识别根证书文件名（供 EAP-TLS cacerts 引用）
ROOT_FILE=$(ls /etc/swanctl/x509ca/*.crt 2>/dev/null | head -1 | xargs -n1 basename)
[ -n "$ROOT_FILE" ] || ROOT_FILE="root.crt"

# ---------- 4. 写入 eap-radius.conf（6.0 插件级配置） ----------
cat > /etc/strongswan.d/charon/eap-radius.conf <<EOF
eap-radius {
	load = yes
	servers {
		primary {
			address = $RADIUS_SERVER
			secret = $RADIUS_SECRET
			auth_port = 1812
			acct_port = 1813
		}
	}
}
EOF
log "已写入 /etc/strongswan.d/charon/eap-radius.conf (RADIUS=$RADIUS_SERVER)"

# ---------- 5. 写入 swanctl.conf（strongSwan 6.0 语法） ----------
cat > /etc/swanctl/swanctl.conf <<EOF
connections {

    # ---------- IKEv2 · EAP-MSCHAPv2（用户名密码，首选） ----------
    ikev2-mschapv2 {
        version = 2
        send_cert = always
        pools = vpnpool
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes256-sha384-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes128-sha384-modp2048,aes192-sha256-modp2048,aes192-sha1-modp2048,aes192-sha384-modp2048,3des-sha256-modp2048,3des-sha1-modp2048,3des-sha384-modp2048,aes256gcm16-prfsha256-modp2048,aes256gcm16-prfsha1-modp2048,aes256gcm16-prfsha384-modp2048,aes128gcm16-prfsha256-modp2048,aes128gcm16-prfsha1-modp2048,aes128gcm16-prfsha384-modp2048,aes256-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-ecp256,aes128-sha256-modp2048
        local {
            auth = pubkey
            certs = $GW_CERT
            id = $GW_ID
        }
        remote {
            auth = eap-radius
            eap_id = %any
        }
        children {
            ikev2-mschapv2 {
                remote_ts = 0.0.0.0/0
            }
        }
    }

    # ---------- IKEv2 · EAP-TLS（客户端证书认证，可选） ----------
    ikev2-eaptls {
        version = 2
        send_cert = always
        pools = vpnpool
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes256-sha384-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes128-sha384-modp2048,aes192-sha256-modp2048,aes192-sha1-modp2048,aes192-sha384-modp2048,3des-sha256-modp2048,3des-sha1-modp2048,3des-sha384-modp2048,aes256gcm16-prfsha256-modp2048,aes256gcm16-prfsha1-modp2048,aes256gcm16-prfsha384-modp2048,aes128gcm16-prfsha256-modp2048,aes128gcm16-prfsha1-modp2048,aes128gcm16-prfsha384-modp2048,aes256-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-ecp256,aes128-sha256-modp2048
        local {
            auth = pubkey
            certs = $GW_CERT
            id = $GW_ID
        }
        remote {
            auth = eap-tls
            eap_id = %any
            cacerts = $ROOT_FILE
        }
        children {
            ikev2-eaptls {
                remote_ts = 0.0.0.0/0
            }
        }
    }
}

pools {
    vpnpool {
        addrs = $POOL_ADDRS
        dns = $DNS1,$DNS2
    }
}

secrets {
}
EOF
log "已写入 /etc/swanctl/swanctl.conf (网关ID=$GW_ID, 证书=$GW_CERT)"

# ---------- 6. 内核转发 ----------
grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
log "已开启内核转发 net.ipv4.ip_forward=1"

# ---------- 7. NAT（出接口自动识别） ----------
IFACE=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
[ -z "$IFACE" ] && IFACE="eth0"
if iptables -t nat -C POSTROUTING -s $POOL_ADDRS -o "$IFACE" -j MASQUERADE 2>/dev/null; then
    :
else
    iptables -t nat -A POSTROUTING -s $POOL_ADDRS -o "$IFACE" -j MASQUERADE 2>/dev/null
fi
netfilter-persistent save >/dev/null 2>&1 || true
log "已配置 NAT: $POOL_ADDRS -> $IFACE (MASQUERADE)"

# ---------- 8. 启动并验证 ----------
systemctl enable strongswan >/dev/null 2>&1 || true
systemctl restart strongswan 2>/dev/null || systemctl restart strongswan-swanctl 2>/dev/null
sleep 2

if systemctl is-active strongswan >/dev/null 2>&1 || systemctl is-active strongswan-swanctl >/dev/null 2>&1; then
    log "strongSwan 服务运行中"
else
    fail "strongSwan 启动失败！请查看: journalctl -u strongswan -n 50"
fi

echo ""
echo "==================== 连接清单 ===================="
swanctl --list-conns 2>/dev/null | grep -E "^ikev2|auth:|certs:|id:" | sed 's/^/  /'
echo "=================================================="
echo ""
log "安装完成！拨号参数: 服务器=$(hostname -I 2>/dev/null | awk '{print $1}')  远程ID=$GW_ID"
log "Windows 需把 PKI/ROOT/{序列号}.crt 安装到受信任的根证书颁发机构"
log "如连接失败请查看: journalctl -u strongswan -f"
