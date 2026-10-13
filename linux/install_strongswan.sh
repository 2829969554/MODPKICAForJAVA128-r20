#!/usr/bin/env bash
# ============================================================================
#  MODPKICA × strongSwan 一键网关部署脚本
#  Debian 12/13 · Ubuntu 24.04+ · strongSwan 5.9/6.0
# ----------------------------------------------------------------------------
#  作用：把一台 Linux 服务器装成 IKEv2 网关，把手机 / Windows / macOS 的
#        EAP-MSCHAPv2（用户名密码）与 EAP-TLS（客户端证书）认证转发到
#        Windows 主机上的 MODPKICA Java RADIUS（UDP 1812 认证 / 1813 计费）。
#
#  用法：
#    sudo bash install_strongswan.sh [RADIUS_SERVER] [RADIUS_SECRET] [网关ID]
#    sudo bash install_strongswan.sh --help
#
#    $1 RADIUS_SERVER  Windows 主机 IP（Java RADIUS 所在）        默认 10.255.228.55
#    $2 RADIUS_SECRET  RADIUS 共享密钥（PKI/CONFIG.txt RADIUSKEY） 默认 mytestkey
#    $3 网关ID          网关证书 CN/SAN（客户端"远程 ID"）         默认 vpn.local
#
#  环境变量（可替代/覆盖参数）：
#    POOL_ADDRS=10.10.0.0/24     客户端地址池（默认）
#    VPN_DNS=223.5.5.5,8.8.8.8   下发给客户端的 DNS（逗号分隔；留空=不下发）
#    GW_CRT=/tmp/gw.crt          网关证书路径（默认 /tmp/gw.crt）
#    GW_KEY=/tmp/gw.key          网关私钥路径（默认 /tmp/gw.key）
#    ROOT_CRT=/tmp/root.crt      根证书路径（默认 /tmp/root.crt）
#    NO_NAT=1                    跳过 NAT/FORWARD/MSS 配置（纯内网互访时用）
#    NO_PERSIST=1                不安装 iptables-persistent、不保存规则
#    RADIUS_TEST=1               强制做 RADIUS 连通性自检（需 radclient）
#
#  证书准备（任选其一）：
#    A. 推荐：拷到 /tmp（脚本会逐项校验配对/SAN/有效期/链接后才部署）
#         scp PKI/CERT/{网关序列号}.crt root@服务器:/tmp/gw.crt
#         scp PKI/KEY/{网关序列号}.key  root@服务器:/tmp/gw.key
#         scp PKI/ROOT/{根序列号}.crt   root@服务器:/tmp/root.crt
#    B. 已放进 /etc/swanctl/{x509,private,x509ca}：脚本按"CN/SAN 含网关ID 且私钥配对"
#         自动挑选（不再盲取目录里第一个证书）
#
#  脚本动作（幂等，可反复执行；覆盖前自动备份 *.bak.<时间戳>）：
#    ① 装包      strongswan / strongswan-pki / libcharon-extra-plugins [ /strongswan-swanctl ]
#    ② 单元解析  停用与 swanctl 冲突的 strongswan-starter
#    ③ 证书部署  配对校验 + serverAuth EKU + 有效期 + **SAN 含本机 IP 检查** + 链接到根
#    ④ eap-radius.conf   RADIUS 地址/密钥/端口 + NAS-Identifier（含可调重传项注释）
#    ⑤ swanctl.conf      4 条连接（密码/证书 × 网关ID/服务器IP）+ 地址池 + DNS
#    ⑥ 内核转发  /etc/sysctl.d/99-modpkica-vpn.conf
#    ⑦ 防火墙    MASQUERADE + FORWARD 双向 + TCP MSS 钳制（幂等，可 NO_NAT=1 跳过）
#    ⑧ 启动验证  systemctl restart → swanctl --load-all → 连接清单 → 监听 → RADIUS 自检
#
#  说明：脚本未使用 `set -e`，关键步骤逐一 `|| fail` 判断（避免外部命令非零返回误伤流程）。
# ============================================================================

set -uo pipefail

# ------------------------------ 帮助 ----------------------------------------
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    # 打印文件头部注释块（NR>1 且遇到第一条可执行语句前的全部 '#' 行）
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
    exit 0
fi

# ------------------------------ 参数 ----------------------------------------
RADIUS_SERVER="${1:-${RADIUS_SERVER:-10.255.228.55}}"
RADIUS_SECRET="${2:-${RADIUS_SECRET:-mytestkey}}"
GW_ID="${3:-${GW_ID:-vpn.local}}"

POOL_ADDRS="${POOL_ADDRS:-10.10.0.0/24}"
VPN_DNS="${VPN_DNS:-223.5.5.5,8.8.8.8}"
NO_NAT="${NO_NAT:-0}"
NO_PERSIST="${NO_PERSIST:-0}"
RADIUS_TEST="${RADIUS_TEST:-0}"

SRC_CRT="${GW_CRT:-/tmp/gw.crt}"
SRC_KEY="${GW_KEY:-/tmp/gw.key}"
SRC_ROOT="${ROOT_CRT:-/tmp/root.crt}"

SWANCTL_DIR=/etc/swanctl
PLUGIN_DIR=/etc/strongswan.d/charon
STAMP="$(date +%Y%m%d-%H%M%S)"

# ------------------------------ 输出 ----------------------------------------
c_ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
c_info() { printf '\033[1;36m[--]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[!!]\033[0m %s\n' "$*"; }
c_bad()  { printf '\033[1;31m[XX]\033[0m %s\n' "$*"; }
fail()   { c_bad "$*"; exit 1; }

# 覆盖写文件前备份（保证可回滚 / 幂等重跑安全）
backup() {
    local f="$1"
    [ -e "$f" ] || return 0
    cp -a "$f" "$f.bak.$STAMP" && c_info "已备份 $f → $f.bak.$STAMP"
}

[ "$(id -u)" = "0" ] || fail "请用 root 或 sudo 运行：sudo bash $0 ${1:-} ${2:-} ${3:-}"

echo "============================================================"
echo " MODPKICA × strongSwan 网关部署"
echo "   RADIUS 服务器 : $RADIUS_SERVER"
echo "   共享密钥      : ${RADIUS_SECRET:0:2}******（${#RADIUS_SECRET} 字符）"
echo "   网关 ID       : $GW_ID"
echo "   客户端地址池  : $POOL_ADDRS        DNS: ${VPN_DNS:-（不下发）}"
echo "============================================================"

# ---------- ① 安装 strongSwan ------------------------------------------------
c_info "① 安装 strongSwan 与依赖 ..."
apt-get update -qq || c_warn "apt-get update 失败，继续尝试安装"
DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confnew \
    strongswan strongswan-pki libcharon-extra-plugins iptables openssl ca-certificates \
    || fail "strongSwan 安装失败（apt 返回非 0），请检查软件源 / 网络"
# swanctl 前端（部分发行版把 swanctl 放在独立包里；装不上不算失败，下面会实测命令）
DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan-swanctl >/dev/null 2>&1 || true
command -v swanctl >/dev/null 2>&1 || fail "未找到 swanctl 命令（请确认 strongswan-swanctl 已安装）"
c_ok "strongSwan 已安装：$(swanctl --version 2>/dev/null | tail -1)"

# ---------- ② systemd 单元解析 ----------------------------------------------
c_info "② 解析 systemd 服务单元 ..."
UNIT=""
for u in strongswan strongswan-swanctl strongswan-starter; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1 \
       && systemctl list-unit-files "$u.service" | grep -q "^$u.service"; then
        [ -n "$UNIT" ] || UNIT="$u"
    fi
done
[ -n "$UNIT" ] || fail "未找到 strongswan 单元，请执行：systemctl list-unit-files | grep strongswan"
if [ "$UNIT" != "strongswan-starter" ] && systemctl is-enabled strongswan-starter.service >/dev/null 2>&1; then
    systemctl disable --now strongswan-starter.service >/dev/null 2>&1 || true
    c_info "已停用 strongswan-starter（/etc/ipsec.conf 与 swanctl 配置互斥）"
fi
c_ok "使用服务单元：$UNIT.service"

# ---------- ③ 证书部署 + 校验 ------------------------------------------------
c_info "③ 部署并校验证书 ..."
mkdir -p "$SWANCTL_DIR/x509" "$SWANCTL_DIR/private" "$SWANCTL_DIR/x509ca" "$PLUGIN_DIR"

san_has() {   # 证书的 CN 或 SAN 是否含指定串
    openssl x509 -in "$1" -noout -subject -ext subjectAltName 2>/dev/null | grep -Fq "$2"
}
key_matches() {   # 证书公钥与私钥配对（SPKI DER SHA-256 比对）
    local a b
    a=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    b=$(openssl pkey -in "$2" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    [ -n "$a" ] && [ "$a" = "$b" ]
}
cert_report() {   # 关键项体检 + SAN-IP 提示
    local crt="$1" tag="网关证书" bits ips localips hit=0 lip cip
    c_ok "$tag：$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed 's/^subject=//')"
    c_ok "$tag 有效期：$(openssl x509 -in "$crt" -noout -dates 2>/dev/null | tr '\n' ' ')"
    if ! openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
        c_warn "$tag 已过期或尚未生效——客户端会直接拒绝"
    fi
    if ! openssl x509 -in "$crt" -noout -text 2>/dev/null | grep -A1 -i "Extended Key Usage" | grep -q "TLS Web Server Authentication"; then
        c_warn "$tag 缺少 serverAuth 增强型密钥用法（EKU 1.3.6.1.5.5.7.3.1）——iOS/Windows 可能拒绝"
    fi
    bits=$(openssl x509 -in "$crt" -noout -text 2>/dev/null | grep -m1 "Public-Key" | grep -o '[0-9]\+' | head -1)
    if [ -n "$bits" ] && [ "$bits" -lt 2048 ]; then
        c_warn "$tag 公钥仅 ${bits} 位：iOS 13+ / Win11 会拒绝 < 2048 位 RSA（根 CA 若为 1024 位同样有风险）"
    fi
    if ! san_has "$crt" "$GW_ID"; then
        c_warn "$tag 的 CN/SAN 里没有「$GW_ID」——客户端「远程 ID」必须填证书里真实存在的名字"
    fi
    ips=$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -o 'IP Address:[0-9.]*' | sed 's/IP Address://' | tr '\n' ' ')
    localips=$(hostname -I 2>/dev/null || true)
    for lip in $localips; do
        for cip in $ips; do
            if [ "$lip" = "$cip" ]; then
                hit=1
            fi
        done
    done
    if [ "$hit" = "1" ]; then
        c_ok "$tag 的 SAN 含本机 IP（Windows 用 IP 拨号可过「证书身份=连接地址」校验）"
    else
        c_warn "==================================================================="
        c_warn " 警告：$tag 的 SAN 里没有本机 IP（SAN IP：${ips:-无}）"
        c_warn " Windows 10/11 自带 VPN 用 IP 拨号会严格校验「证书身份 = 连接地址」，"
        c_warn " 症状是「在连接完成前，连接被远程计算机终止」。请重签网关证书并把"
        c_warn " SAN 同时填上 $GW_ID 与本机 IP（$(echo "$localips" | awk '{print $1}')）。"
        c_warn " 详见《strongSwan接入指南》第四节。"
        c_warn "==================================================================="
    fi
}

if [ -f "$SRC_CRT" ] && [ -f "$SRC_KEY" ] && [ -f "$SRC_ROOT" ]; then
    cp -f "$SRC_CRT"  "$SWANCTL_DIR/x509/gw.crt"
    cp -f "$SRC_KEY"  "$SWANCTL_DIR/private/gw.key"
    cp -f "$SRC_ROOT" "$SWANCTL_DIR/x509ca/root.crt"
    GW_CERT=gw.crt; GW_KEY=gw.key; ROOT_FILE=root.crt
    c_ok "证书已从 $SRC_CRT / $SRC_KEY / $SRC_ROOT 部署为 gw.crt / gw.key / root.crt"
else
    c_info "未在 /tmp 找到 gw.crt+gw.key+root.crt，改为复用 $SWANCTL_DIR 下已部署证书 ..."
    GW_CERT=""
    for crt in "$SWANCTL_DIR"/x509/*.crt; do
        [ -f "$crt" ] || continue
        base="$(basename "$crt" .crt)"
        if [ -f "$SWANCTL_DIR/private/$base.key" ] \
           && san_has "$crt" "$GW_ID" && key_matches "$crt" "$SWANCTL_DIR/private/$base.key"; then
            GW_CERT="$base.crt"; GW_KEY="$base.key"
            break
        fi
    done
    [ -n "$GW_CERT" ] || fail "未找到可用证书。请先拷证书：scp PKI/CERT/{序列号}.crt root@本机:/tmp/gw.crt（连同 .key 与 /tmp/root.crt），或指定 GW_CRT=/path/gw.crt GW_KEY=/path/gw.key ROOT_CRT=/path/root.crt"
    GW_CERT="$(basename "$GW_CERT")"; GW_KEY="$(basename "$GW_KEY")"
    ROOT_FILE="$(basename "$(ls "$SWANCTL_DIR"/x509ca/*.crt 2>/dev/null | head -1)" 2>/dev/null || true)"
    [ -n "$ROOT_FILE" ] || fail "未找到根证书（$SWANCTL_DIR/x509ca/*.crt），请把 PKI/ROOT/{序列号}.crt 拷到 /tmp/root.crt 后重跑"
    c_ok "复用已有证书：$GW_CERT / $GW_KEY（CN/SAN 含 $GW_ID 且私钥配对）"
fi

chown root:root "$SWANCTL_DIR"/x509/* "$SWANCTL_DIR"/private/* "$SWANCTL_DIR"/x509ca/* 2>/dev/null || true
find "$SWANCTL_DIR/private" -name '*.key' -exec chmod 600 {} \;
chmod 644 "$SWANCTL_DIR"/x509/*.crt "$SWANCTL_DIR"/x509ca/*.crt 2>/dev/null || true

key_matches "$SWANCTL_DIR/x509/$GW_CERT" "$SWANCTL_DIR/private/$GW_KEY" \
    || fail "网关证书与私钥不配对（$GW_CERT ↔ $GW_KEY），请检查导出/拷贝的文件"
c_ok "证书 / 私钥配对校验通过"
cert_report "$SWANCTL_DIR/x509/$GW_CERT"
if openssl verify -CAfile "$SWANCTL_DIR/x509ca/$ROOT_FILE" "$SWANCTL_DIR/x509/$GW_CERT" >/dev/null 2>&1; then
    c_ok "证书链校验通过（信任锚：$ROOT_FILE）"
else
    c_warn "网关证书无法直接用 $ROOT_FILE 验证（可能签自中间 CA）——客户端需装完整信任链"
fi
c_ok "根证书：$ROOT_FILE —— 所有客户端都必须安装它（否则链验证失败）"

# ---------- ④ eap-radius 插件配置 -------------------------------------------
c_info "④ 写入 $PLUGIN_DIR/eap-radius.conf ..."
backup "$PLUGIN_DIR/eap-radius.conf"
cat > "$PLUGIN_DIR/eap-radius.conf" <<EOF
# MODPKICA × strongSwan —— RADIUS 转发插件（strongSwan 5.9/6.0 通用插件级配置）
# 由 linux/install_strongswan.sh 生成于 $STAMP
eap-radius {
    load = yes

    # 写进 Access-Request 的 NAS-Identifier，便于在 RADIUS 日志里区分网关
    nas_identifier = $(hostname)

    servers {
        primary {
            address   = $RADIUS_SERVER
            secret    = $RADIUS_SECRET
            auth_port = 1812
            acct_port = 1813
        }
    }

    # ---- 可调项（默认即可；仅在确有必要时放开，例如链路丢包严重）----
    # sockets            = 1     # 每服务器 UDP socket 数
    # timeout            = 5     # 等待 RADIUS 响应（秒）
    # retransmit_tries   = 3     # 无响应时重传次数
    # retransmit_timeout = 2.0   # 首次重传间隔（秒）
    # accounting         = yes   # 是否转发计费（Acct-Request → 1813）
    # 提示：MODPKICA v1.28-r20 起 EAP-TLS 已按 RFC 3748 §5.1 做「事务化重传重放」，
    #       网关整包重传不会再打乱 TLS 状态机，默认重传参数无需调整。
}
EOF
c_ok "已写入 eap-radius.conf（RADIUS=$RADIUS_SERVER:1812/1813，nas_identifier=$(hostname)）"

# ---------- ⑤ swanctl 配置 ---------------------------------------------------
c_info "⑤ 写入 $SWANCTL_DIR/swanctl.conf ..."
LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$LOCAL_IP" ] || fail "无法确定本机 IP（hostname -I 为空），请检查网络配置"
# IKE 提议集合：现代算法在前（GCM/ECP），兼容项兜底（CBC/MODP）；
# 客户端只需命中其中一条；iOS / Windows SChannel / 安卓 strongSwan 均可协商。
IKE_PROPOSALS="aes256gcm16-prfsha256-ecp256,aes128gcm16-prfsha256-ecp256,aes256gcm16-prfsha384-ecp384,aes256-sha256-ecp256,aes128-sha256-ecp256,aes256-sha384-ecp384,aes256-sha256-ecp384,aes256-sha256-ecp521,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256gcm16-prfsha256-modp2048,aes128gcm16-prfsha256-modp2048,aes256-sha256-modp3072,aes256-sha384-modp4096"
DNS_LINE=""
if [ -n "$VPN_DNS" ]; then DNS_LINE="        dns = $VPN_DNS"; fi

backup "$SWANCTL_DIR/swanctl.conf"
cat > "$SWANCTL_DIR/swanctl.conf" <<EOF
# MODPKICA × strongSwan 网关连接配置（strongSwan 5.9/6.0 · swanctl 语法）
# 由 linux/install_strongswan.sh 生成于 $STAMP
#   ① ikev2-mschapv2     用户名密码，客户端「远程 ID」= $GW_ID
#   ② ikev2-mschapv2-ip  用户名密码，客户端「远程 ID」= $LOCAL_IP（Windows 留空远程 ID 时）
#   ③ ikev2-eaptls       客户端证书（EAP-TLS），远程 ID = $GW_ID
#   ④ ikev2-eaptls-ip    客户端证书（EAP-TLS），远程 ID = $LOCAL_IP
# 所有认证都经 eap-radius 转发到 MODPKICA Java RADIUS（见 charon/eap-radius.conf）

connections {

    # ---------- ① 用户名密码（EAP-MSCHAPv2 → RADIUS） ----------
    ikev2-mschapv2 {
        version   = 2
        send_cert = always          # 无条件下发网关证书（iOS / Windows 必需）
        pools     = vpnpool
        proposals = $IKE_PROPOSALS
        local {
            auth  = pubkey          # 网关以证书证明身份
            certs = $GW_CERT
            id    = $GW_ID
        }
        remote {
            auth   = eap-radius     # EAP 整包转发 RADIUS（eap-radius 插件）
            eap_id = %any           # 接受任意 EAP 身份，真实账号由 RADIUS 判定
        }
        children {
            ikev2-mschapv2 {
                remote_ts = 0.0.0.0/0
            }
        }
    }

    # ---------- ② 用户名密码（远程 ID = 服务器 IP 的客户端） ----------
    ikev2-mschapv2-ip {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = $IKE_PROPOSALS
        local {
            auth  = pubkey
            certs = $GW_CERT
            id    = $LOCAL_IP
        }
        remote {
            auth   = eap-radius
            eap_id = %any
        }
        children {
            ikev2-mschapv2-ip {
                remote_ts = 0.0.0.0/0
            }
        }
    }

    # ---------- ③ 客户端证书（EAP-TLS → RADIUS，v1.28-r20 已验证 iOS/Win/安卓） ----------
    ikev2-eaptls {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = $IKE_PROPOSALS
        local {
            auth  = pubkey
            certs = $GW_CERT
            id    = $GW_ID
        }
        remote {
            auth    = eap-tls       # 客户端证书认证，EAP-TLS 报文同样转发 RADIUS
            eap_id  = %any
            cacerts = $ROOT_FILE    # 先由网关预筛（只收本 PKI 根签发的客户端证书）
        }
        children {
            ikev2-eaptls {
                remote_ts = 0.0.0.0/0
            }
        }
    }

    # ---------- ④ 客户端证书（远程 ID = 服务器 IP 的客户端） ----------
    ikev2-eaptls-ip {
        version   = 2
        send_cert = always
        pools     = vpnpool
        proposals = $IKE_PROPOSALS
        local {
            auth  = pubkey
            certs = $GW_CERT
            id    = $LOCAL_IP
        }
        remote {
            auth    = eap-tls
            eap_id  = %any
            cacerts = $ROOT_FILE
        }
        children {
            ikev2-eaptls-ip {
                remote_ts = 0.0.0.0/0
            }
        }
    }
}

pools {
    vpnpool {
        addrs = $POOL_ADDRS
$DNS_LINE
    }
}

# strongSwan 6.0 已移除 xauth-radius 插件，Cisco IKEv1+XAUTH 场景不再支持；
# 本方案只用 IKEv2，secrets 段保留为空。
secrets {
}
EOF
c_ok "已写入 swanctl.conf（4 条连接 / 网关ID=$GW_ID / 证书=$GW_CERT / 池=$POOL_ADDRS）"

# ---------- ⑥ 内核转发 -------------------------------------------------------
c_info "⑥ 内核转发 ..."
cat > /etc/sysctl.d/99-modpkica-vpn.conf <<EOF
# MODPKICA × strongSwan 网关（install_strongswan.sh 生成于 $STAMP）
net.ipv4.ip_forward = 1
EOF
sysctl -q --system 2>/dev/null || sysctl -q -p /etc/sysctl.d/99-modpkica-vpn.conf
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ] && c_ok "net.ipv4.ip_forward=1 已生效" \
    || c_warn "ip_forward 未生效，请手动执行 sysctl -w net.ipv4.ip_forward=1"

# ---------- ⑦ NAT / FORWARD / MSS -------------------------------------------
if [ "$NO_NAT" = "1" ]; then
    c_info "⑦ 已按 NO_NAT=1 跳过 NAT / FORWARD / MSS 配置"
else
    c_info "⑦ 防火墙规则（NAT + FORWARD 双向 + TCP MSS 钳制）..."
    IFACE="$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')"
    if [ -z "$IFACE" ]; then
        IFACE="$(ip -o link show up 2>/dev/null | awk -F': ' '$2 != "lo" {print $2; exit}')"
    fi
    [ -n "$IFACE" ] || fail "无法识别出接口，请手动配置 NAT，或用 NO_NAT=1 跳过"
    rule() {   # 幂等追加：已存在则跳过
        local t="$1"; shift
        iptables -t "$t" -C "$@" 2>/dev/null || iptables -t "$t" -A "$@" || return 1
    }
    rule nat POSTROUTING -s "$POOL_ADDRS" -o "$IFACE" -j MASQUERADE \
        || fail "NAT 规则写入失败（iptables）"
    rule filter FORWARD -s "$POOL_ADDRS" -j ACCEPT || fail "FORWARD 规则写入失败"
    rule filter FORWARD -d "$POOL_ADDRS" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
        || fail "FORWARD 回程规则写入失败"
    # TCP MSS 钳制：避免 VPN 客户端大包进黑洞（典型症状「能 ping 不能开网页」）
    rule mangle FORWARD -s "$POOL_ADDRS" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
        || c_warn "MSS 钳制规则写入失败（不致命，但客户端可能出现网页打不开）"
    c_ok "已配置：MASQUERADE($POOL_ADDRS → $IFACE) + FORWARD 双向 + MSS 钳制"

    if [ "$NO_PERSIST" != "1" ]; then
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 && c_ok "iptables 规则已持久化" \
                || c_warn "netfilter-persistent save 失败，重启后规则会丢"
        else
            if DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1 && c_ok "已安装 iptables-persistent 并保存规则" \
                    || c_warn "规则保存失败，请手动 netfilter-persistent save"
            else
                c_warn "iptables-persistent 安装失败：规则重启后会丢失（可用 NO_PERSIST=1 静默跳过）"
            fi
        fi
    fi
fi

# ---------- ⑧ 启动与验证 -----------------------------------------------------
c_info "⑧ 启动 $UNIT.service 并验证 ..."
systemctl daemon-reload
systemctl enable "$UNIT.service" >/dev/null 2>&1 || true
systemctl restart "$UNIT.service"
for i in $(seq 1 10); do
    systemctl is-active --quiet "$UNIT.service" && break
    sleep 1
done
if ! systemctl is-active --quiet "$UNIT.service"; then
    journalctl -u "$UNIT.service" -n 30 --no-pager || true
    fail "$UNIT.service 启动失败（上方为最近 30 行日志）"
fi
c_ok "$UNIT.service 运行中"

# 主动加载配置：配置语法错误会在这里显式报错（而不是静默空清单）
LOAD_OUT="$(swanctl --load-all 2>&1 || true)"
printf '%s\n' "$LOAD_OUT" | sed 's/^/     /'
if printf '%s' "$LOAD_OUT" | grep -qiE "error|failed|unable"; then
    fail "swanctl 配置加载报错（见上方输出）；常见原因：证书文件名不符 / 语法残留（5.x 旧写法）"
fi

CONNS="$(swanctl --list-conns 2>/dev/null || true)"
echo ""
echo "==================== 连接清单 ===================="
printf '%s\n' "$CONNS" | sed 's/^/  /'
echo "=================================================="
for c in ikev2-mschapv2 ikev2-mschapv2-ip ikev2-eaptls ikev2-eaptls-ip; do
    if ! printf '%s' "$CONNS" | grep -q "$c"; then
        fail "连接 $c 未出现在清单中——请检查上方 swanctl 输出与 $SWANCTL_DIR/swanctl.conf"
    fi
done
c_ok "4 条连接（用户名密码 / 客户端证书 × 网关ID / 服务器IP）均已加载"

if ss -lunp 2>/dev/null | grep -qE ':(500|4500)\b'; then
    c_ok "已监听 UDP 500 / 4500（IKEv2）"
else
    c_warn "未看到 UDP 500/4500 监听：请检查 ss -lunp | grep -E ':500|:4500' 与 $UNIT.service 状态"
fi

if command -v radclient >/dev/null 2>&1; then
    c_info "RADIUS 连通性自检（radclient 探针账号 modpkica-probe）..."
    ROUT="$(printf 'User-Name=modpkica-probe\nUser-Password=probe\n' \
            | radclient -t 3 -r 2 "$RADIUS_SERVER:1812" auth "$RADIUS_SECRET" 2>&1 || true)"
    if printf '%s' "$ROUT" | grep -qi "Access-Reject"; then
        c_ok "RADIUS 可达、共享密钥正确（Access-Reject = 服务器活着且已校验密钥/账号）"
    else
        c_warn "RADIUS 自检未得到期望响应：$(printf '%s' "$ROUT" | tr '\n' ' ')"
        c_warn "排查：Windows 防火墙放行 UDP 1812；eap-radius.conf 的 address / secret；MAIN 是否在运行"
    fi
elif [ "$RADIUS_TEST" = "1" ]; then
    c_warn "RADIUS_TEST=1 但未安装 radclient：apt install -y freeradius-utils"
else
    c_info "未安装 radclient，跳过 RADIUS 自检。手动验证："
    echo "     sudo apt install -y freeradius-utils"
    echo "     echo -e 'User-Name=test,User-Password=test' | radclient -t 3 $RADIUS_SERVER:1812 auth $RADIUS_SECRET"
fi

# ---------- 收尾 -------------------------------------------------------------
cat <<EOF

============================================================
 部署完成 ✔    网关地址 = $LOCAL_IP
============================================================
 [客户端拨号参数]
   服务器地址 : $LOCAL_IP
   远程 ID    : $GW_ID（或留空 / 填 $LOCAL_IP——两条连接都已就绪）
   认证方式   : 用户名密码（PKI/USERS.txt 账号）或 客户端证书（EAP-TLS）
   地址池     : $POOL_ADDRS      DNS: ${VPN_DNS:-不下发}

 [客户端必须安装根证书]
   根证书 : $SWANCTL_DIR/x509ca/$ROOT_FILE（对应 Windows 主机 PKI/ROOT/{序列号}.crt）
   iOS      : 安装描述文件后，再到「设置 → 通用 → 关于本机 → 证书信任设置」打勾
   Windows  : 导入「受信任的根证书颁发机构（本地计算机）」
   Android  : 设置 → 安全 → 加密与凭据 → 安装 CA 证书

 [Windows 主机防火墙放行]（管理员 PowerShell，单行可直接粘贴）
   New-NetFirewallRule -DisplayName "MODPKICA RADIUS from VPN server" -Direction Inbound -Protocol UDP -LocalPort 1812,1813 -RemoteAddress $LOCAL_IP -Action Allow

 [排障入口]
   网关实时日志 : journalctl -u $UNIT.service -f
   活动会话     : swanctl --list-sas
   RADIUS 日志  : WebAdmin(8080) → Radius服务管理 → 服务器日志
   症状 → 原因  : 《strongSwan接入指南》第 12 节「故障排查」
============================================================
EOF
