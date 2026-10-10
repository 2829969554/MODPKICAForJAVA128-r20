# MODPKICA RADIUS × strongSwan 网关接入指南

> 用途：在 Linux 服务器上部署 strongSwan IKEv2/IPsec 网关，把手机 / Windows / macOS 的 VPN 认证转发到你 Windows 上的 Java RADIUS 服务（UDP 1812/1813）。
> **重要版本说明**：Debian 13 自带 **strongSwan 6.0.x**，配置语法与 5.x（Ubuntu 24.04 的 5.9.x）差异很大，下文按 6.0 语法编写；5.9 差异已在文末【版本差异】标注。
> **实测状态（2026-10-10）**：**EAP-MSCHAPv2（用户名密码）与 EAP-TLS（客户端证书）两条链路均已在手机 strongSwan 6.0.3 实测打通**；EAP-TLS 依赖服务端按 RFC 5216 §2.4 导出 MSK 并经 RFC 2548 §2.4.3 以 **MS-MPPE 32+32B** 下发（MODPKICA v1.28-r16 已支持）。

## 目录

1. [架构与前提](#一架构与前提)
2. [方式一：一键脚本安装（推荐）](#二方式一一键脚本安装推荐)
3. [方式二：手工安装配置](#三方式二手工安装配置)
4. [用 MODPKICA 签发网关证书](#四用-modpkica-签发网关证书)
5. [拷贝证书到服务器](#五拷贝证书到服务器)
6. [swanctl 配置（strongSwan 6.0 语法）](#六swanctl-配置strongswan-60-语法)
7. [eap-radius 插件配置](#七eap-radius-插件配置)
8. [Windows 防火墙放行](#八windows-防火墙放行)
9. [启动与验证](#九启动与验证)
10. [手机 / Windows / macOS 拨号配置](#十手机--windows--macos-拨号配置)
11. [L2TP（可选）](#十一l2tp可选)
12. [故障排查](#十二故障排查)
13. [版本差异（5.9 ↔ 6.0）](#十三版本差异59--60)

---

## 一、架构与前提

```
手机/Windows/macOS (IKEv2 EAP-MSCHAPv2 / EAP-TLS)
   │  IKEv2 (UDP 500 / 4500)
   ▼
Linux strongSwan 网关
   │  RADIUS 转发 (UDP 1812 认证 / 1813 计费)
   ▼
Windows 主机 Java RADIUS (modpkica.MAIN)
```

**前提清单**：
- Linux 服务器已装好（Debian 13 / Ubuntu 24.04+），网卡桥接或 NAT，与 Windows 同网段可达，**静态 IP**（下文示例 `10.255.228.225`）
- Windows 主机局域网 IP（RADIUS 所在，下文示例 `10.255.228.55`）
- Java RADIUS 已运行（MAIN 服务），**共享密钥** = WebAdmin → Radius服务管理 配置值（默认 `mytestkey`，见 `PKI/CONFIG.txt` 的 `RADIUSKEY`）
- 测试账号（PKI/USERS.txt，WebAdmin → 用户管理 中添加）
- 已签发网关证书 + 根证书（见第四节），根证书需安装到所有拨号客户端

## 二、方式一：一键脚本安装（推荐）

项目提供 `linux/install_strongswan.sh`，一条命令完成安装 + 配置 + 启动：

```bash
# 1) 把证书拷到服务器 /tmp（证书 = 网关证书 .crt/.key + 根证书 .crt，见第四节）
scp PKI/CERT/f7679b33352bd0d0e150e8594606c01f.crt   root@10.255.228.225:/tmp/gw.crt
scp PKI/KEY/f7679b33352bd0d0e150e8594606c01f.key    root@10.255.228.225:/tmp/gw.key
scp PKI/ROOT/7712d9352e6038ce78e57e3f572cec74.crt   root@10.255.228.225:/tmp/root.crt

# 2) 把脚本也拷过去并执行（root 或 sudo）
scp linux/install_strongswan.sh root@10.255.228.225:/tmp/
ssh root@10.255.228.225 "sudo bash /tmp/install_strongswan.sh 10.255.228.55 mytestkey vpn.local"

# 参数：$1=RADIUS服务器IP  $2=RADIUS共享密钥  $3=网关ID(证书CN/SAN，默认vpn.local)
# 证书自动从 /tmp/gw.crt /tmp/gw.key /tmp/root.crt 部署；也可改用其它路径见脚本内说明
```

脚本自动完成：安装 strongSwan 6.x → 部署证书 → 写入 `swanctl.conf` 与 `eap-radius.conf` → 开启内核转发 → 配置 NAT → 启动并验证 `swanctl --list-conns`。

## 三、方式二：手工安装配置

```bash
sudo apt update
sudo apt install strongswan strongswan-pki libcharon-extra-plugins
```

> **Debian 13 / strongSwan 6.0**：核心插件（eap-radius、eap-mschapv2、openssl、vici 等）随 `libcharon-extra-plugins` 已装入 `/usr/lib/ipsec/plugins/`。
> 启动 `swanctl --version` 时若看到 `plugin 'aes' failed to load` 之类提示——**无害**：6.0 的加解密由 openssl 插件后端提供，旧式 aes/sha2/gmp 插件已不存在，忽略即可。

## 四、用 MODPKICA 签发网关证书

WebAdmin → 签发证书 页面签一张 **终端证书（E）**：

| 参数 | 值 |
|---|---|
| 证书类型 | 终端证书 |
| 颁发者 | 根证书（R）或中间 CA（C） |
| 密钥算法 | RSA 2048（推荐） |
| 哈希算法 | SHA256 |
| 增强型密钥用法 | **服务器身份验证 (1.3.6.1.5.5.7.3.1)** |
| SAN 域名 | `vpn.local`（或你的域名） |
| SAN IP | **Linux 服务器 IP，如 `10.255.228.225`**（见下方警告） |
| 扩展控制 | **noAIA**（推荐，见下方说明） |

> ⚠️ **SAN 必须包含服务器 IP**：Windows（尤其 Win11）原生 IKEv2 会严格校验"证书身份 = 连接地址"。若证书 SAN 里没有服务器 IP，客户端会**静默丢弃连接**（症状：报"在连接完成前，连接被远程计算机终止"或"远程计算机终止连接"）。手机 strongSwan App 可只用域名（远程 ID 填域名），但 Windows 系统自带 VPN 用 IP 拨号时必须有 IP SAN。
>
> ⚠️ **noAIA 参数**：MakeCert 第 10 参数传 `noAIA` 时不签发 AIA/CRL 扩展（OCSP/CRL 不再指向 `localhost:80`），避免客户端在验证时访问不可达的 localhost 吊销服务导致超时/失败。命令行签发示例：
>
> ```bash
> java "-Dfile.encoding=UTF-8" -cp "out;BC185\*" modpkica.MakeCert \
>   "C=CN,L=newer york,O=China IT Boys,OU=IT Clubs,CN=vpn.local" \
>   2048 sha256 1 1 0 1 "vpn.local" "10.255.228.225,127.0.0.1" noAIA \
>   7712d9352e6038ce78e57e3f572cec74 RSA
> ```

签发后导出：
- 网关证书：`PKI/CERT/{序列号}.crt`（如 `f7679b33352bd0d0e150e8594606c01f.crt`）
- 网关私钥：`PKI/KEY/{序列号}.key`
- 根证书：`PKI/ROOT/{序列号}.crt`（如 `7712d9352e6038ce78e57e3f572cec74.crt`）

> **EAP-TLS 客户端证书**：同样在 WebAdmin → 签发证书 签发一张终端证书（E），增强型密钥用法勾选"服务器身份验证 + 客户端身份验证"；证书+私钥打包为 `.pfx` 供手机 strongSwan 导入（见 10.2 节）。手机 strongSwan 验证客户端证书时用 `PKI/ROOT/{根序列号}.crt`（即 swanctl `x509ca/` 下那份）作信任锚。

## 五、拷贝证书到服务器

```bash
sudo mkdir -p /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/x509ca
sudo mv /tmp/gw.crt  /etc/swanctl/x509/{序列号}.crt
sudo mv /tmp/gw.key  /etc/swanctl/private/{序列号}.key
sudo mv /tmp/root.crt /etc/swanctl/x509ca/{序列号}.crt
sudo chown root:root /etc/swanctl/x509/* /etc/swanctl/private/* /etc/swanctl/x509ca/*
sudo chmod 600 /etc/swanctl/private/*.key
```

> 6.0 中证书文件**以真实文件名（序列号）引用**，不要改名为 `gwCert.pem`（旧指南命名，6.0 照样可用但无必要）。

## 六、swanctl 配置（strongSwan 6.0 语法）

编辑 `/etc/swanctl/swanctl.conf`（整体替换，`{序列号}` 换成你的网关证书序列号）：

```
connections {

    # ---------- ① IKEv2 · EAP-MSCHAPv2（用户名密码，首选） ----------
    ikev2-mschapv2 {
        version = 2
        send_cert = always
        pools = vpnpool
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256gcm16-prfsha256-modp2048,aes128gcm16-prfsha256-modp2048,aes256-sha256-ecp256,aes128-sha256-ecp256
        local {
            auth = pubkey
            certs = {序列号}.crt
            id = vpn.local
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

    # ---------- ② IKEv2 · EAP-TLS（客户端证书认证，可选） ----------
    ikev2-eaptls {
        version = 2
        send_cert = always
        pools = vpnpool
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256gcm16-prfsha256-modp2048,aes128gcm16-prfsha256-modp2048,aes256-sha256-ecp256,aes128-sha256-ecp256
        local {
            auth = pubkey
            certs = {序列号}.crt
            id = vpn.local
        }
        remote {
            auth = eap-tls
            eap_id = %any
            cacerts = 7712d9352e6038ce78e57e3f572cec74.crt
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
        addrs = 10.10.0.0/24
        dns = 223.5.5.5,8.8.8.8
    }
}

secrets {
    # 预留：若日后启用 IKEv1 PSK 场景
}
```

> 说明：
> - 6.0 中 **EAP 走 RADIUS 的服务器配置不写在这里**，改在 `/etc/strongswan.d/charon/eap-radius.conf`（见下一节）；connection 里 `remote { auth = eap-radius }` 即可。
> - 旧指南的 `eap_radius { servers { ... } }` / `xauth_radius` 子块是 **5.x 语法，6.0 会解析失败导致整份配置加载失败**（`swanctl --list-conns` 空、服务 failed）。
> - **ikev1-xauth（Cisco）已不支持**：strongSwan 6.0 移除了 xauth-radius 插件，Cisco IKEv1+XAUTH 场景不再可用，不要添加该连接。
> - `id = vpn.local` 必须与网关证书的 CN/SAN 一致（证书是 `CN=vpn.local`）。

## 七、eap-radius 插件配置

创建 `/etc/strongswan.d/charon/eap-radius.conf`：

```
eap-radius {
	load = yes
	servers {
		primary {
			address = 10.255.228.55
			secret = mytestkey
			auth_port = 1812
			acct_port = 1813
		}
	}
}
```

> `address` = Windows 主机 IP；`secret` = RADIUS 共享密钥（`PKI/CONFIG.txt` 的 `RADIUSKEY`）；端口默认 1812/1813。

## 八、Windows 防火墙放行

在 Windows（管理员 PowerShell）放行来自服务器的 RADIUS 流量：

```powershell
# 放行 UDP 1812/1813 来自 Linux 服务器（按你的服务器 IP 或子网）
New-NetFirewallRule -DisplayName "MODPKICA RADIUS from VPN server" `
  -Direction Inbound -Protocol UDP -LocalPort 1812,1813 `
  -RemoteAddress 10.255.228.225 -Action Allow
```

确认 Java RADIUS 监听：
```powershell
Get-NetUDPEndpoint -LocalPort 1812
```

## 九、启动与验证

```bash
sudo systemctl enable --now strongswan          # Debian 13：服务名是 strongswan（不是 strongswan-swanctl）
sudo systemctl restart strongswan
sudo swanctl --list-conns                        # 应看到 ikev2-mschapv2 / ikev2-eaptls
sudo swanctl --list-sas                          # 有活动会话时显示
```

开启内核转发 + NAT（让 VPN 客户端访问内网/外网）：

```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
# 出接口换成服务器的实际网卡（ip route 看默认路由那块的接口名，如 enp0s3/eth0）
sudo iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o enp0s3 -j MASQUERADE
sudo apt install -y iptables-persistent && sudo netfilter-persistent save
```

## 十、手机 / Windows / macOS 拨号配置

### 10.1 用户名密码（EAP-MSCHAPv2，首选）

**iOS（设置 → 通用 → VPN 与设备管理）：**
1. 先安装根证书（`PKI/ROOT/{序列号}.crt`）并**完全信任**（设置 → 通用 → 关于本机 → 证书信任设置）
2. 添加 VPN：类型 `IKEv2`，服务器填 `10.255.228.225`，远程 ID 填 `vpn.local`（与证书 SAN 一致），本地 ID 留空，鉴定方式选"用户名"，填 PKI/USERS.txt 账号

**Android（strongSwan App 或系统 VPN）：**
- strongSwan App：类型 `IKEv2 EAP (用户名/密码)`，服务器 `10.255.228.225`，服务器标识 `vpn.local`，导入/信任根证书后连接
- 系统 VPN（部分安卓）：类型 `IKEv2/IPsec MSCHAPv2`，服务器地址 `10.255.228.225`，IPSec 标识符 `vpn.local`，账号密码同上

### 10.2 客户端证书（EAP-TLS，实测打通）

手机 strongSwan App 用**客户端证书 + 私钥**做 EAP-TLS 认证（证书由 MODPKICA 签发，EKU 需含服务器身份验证或客户端身份验证，见第四节）：

1. **签发客户端证书**：WebAdmin → 签发证书，证书类型选"终端证书"，颁发者选"签发根证书"（R，也可选中间 CA），增强型密钥用法勾选"服务器身份验证 + 客户端身份验证"；签发成功后证书自动落盘 `PKI/CERT/{序列号}.crt`、私钥 `PKI/KEY/{序列号}.key`
2. **导出手机可导入的 `.pfx`**：WebAdmin → 证书库（CERTS.txt）→ 右键该证书 → 下载证书 → 下载证书+私钥(.pfx)（含 END+CA+ROOT 链）；示例产物：`PKI/b53080_client_2048.pfx`，密码 `12345678`
3. **手机导入**：strongSwan App → 配置 → 添加 VPN：
   - 类型：**IKEv2 Certificate**（或 IKEv2 EAP + 客户端证书）
   - 服务器：`10.255.228.225`
   - 服务器标识（远程 ID）：`vpn.local`
   - 本地标识：`vpn.local`（或留空，服务端以证书 DN 识别用户）
   - 导入 `.pfx` 客户端证书（strongSwan App：配置页"证书"→ 从文件导入，输入 pfx 密码）
   - 信任根证书（CA 证书：`PKI/ROOT/{根序列号}.crt`）
3. 连接：服务端以客户端证书 DN 作为用户名放行（`PKI/USERS.txt` 无需为证书用户建账号；日志显示 `用户=CN=vpn.local...（客户端证书: ...）`）

> **服务端 MSK/MS-MPPE 说明**：EAP-TLS 认证通过后，MODPKICA 按 RFC 5216 §2.4 手工导出 64B MSK（`PRF(master_secret,"client EAP encryption",client_random‖server_random)`），并经 RFC 2548 §2.4.3 以 **MS-MPPE-Recv-Key=MSK[0..32) / MS-MPPE-Send-Key=MSK[32..64)（32+32B）** 随 Access-Accept 下发；strongSwan 网关 `eap-radius` 解密后重组 64B MSK 完成 IKEv2 AUTH（RFC 7296 §2.16）。此链路（EAP-TLS 证书登录）已在手机 strongSwan 6.0.3 实测打通。

**Windows 10/11 系统自带 VPN：**
1. 安装根证书到"受信任的根证书颁发机构"（双击 `PKI/ROOT/{序列号}.crt` → 安装证书 → 本地计算机 → 受信任的根证书颁发机构）——**必须装，否则证书链验证失败**
2. 设置 → 网络和 Internet → VPN → 添加 VPN：
   - VPN 提供商：Windows（内置）
   - 连接名称：自定
   - 服务器名称或地址：`10.255.228.225`
   - VPN 类型：**IKEv2**
   - 登录信息的类型：用户名和密码
3. 连接后如提示"服务器证书无效"，确认：(a) 根证书已装到受信任根；(b) 网关证书 SAN 含 `10.255.228.225`

**macOS（系统 VPN）：**
- 类型 `IKEv2`，服务器地址 `10.255.228.225`，远程 ID `vpn.local`，本地证书选已安装的客户端证书（或用 EAP 用户名密码），信任根证书后连接

## 十一、L2TP（可选）

L2TP = IPsec(PSK) 隧道 + L2TP(1701) + PPP 认证，较繁琐且 6.0 下仍需 IPsec IKEv1，建议优先跑通 IKEv2。如需：
```bash
sudo apt install xl2tpd ppp libpam-radius-auth
```
`/etc/xl2tpd/xl2tpd.conf`、`/etc/ppp/options.xl2tpd`、PAM 转发配置可参考 5.x 时代文档；注意 6.0 的 swanctl 中 IPsec(PSK) 连接写法同样使用新语法。

## 十二、故障排查

| 症状 | 排查 |
|---|---|
| 连接建立失败 / 被远程终止 | `sudo journalctl -u strongswan -f` 看 charon 日志；重点看 `deleting half open IKE_SA`（=客户端收到服务器证书后静默丢弃 → **证书 SAN 不匹配**）或 `no acceptable proposal`（算法） |
| 手机能连、Windows 不能连 | 证书 SAN 缺服务器 IP（Win 严格校验）；根证书未装到 Windows 受信任根 |
| 认证失败 | Windows 侧 Java 日志（WebAdmin → Radius服务管理 → 服务器日志）；确认共享密钥一致 |
| 手机提示证书无效 | 根证书未安装/未信任；远程 ID 与证书 SAN 不匹配（用 `vpn.local`） |
| EAP-TLS 握手成功但 `N(AUTH_FAILED)` | 手机日志 `EAP method EAP_TLS succeeded, MSK established` 后网关回 AUTHENTICATION_FAILED——**服务端 Access-Accept 未下发 MS-MPPE 32+32B 密钥**（RFC 2548 §2.4.3），网关无法恢复与手机一致的 MSK。确认 MODPKICA 为 **v1.28-r16 及以上**；查看 WebAdmin → Radius服务管理 → 服务器日志应出现 `[DBG] EAP-TLS 已下发 MS-MPPE 密钥 32+32B`；若仅 `16+16B` 或 `[WARN] 未导出 MSK` 则服务端版本不对 |
| RADIUS 无响应 | Windows 防火墙未放行 UDP 1812；`eap-radius.conf` 的 address/secret 错误 |
| 路由不通 | `sysctl net.ipv4.ip_forward=1`；NAT 规则；服务器出接口名写错 |
| charon 起不来 | `swanctl --list-conns` 报 Connection refused = 服务 failed；`journalctl -u strongswan` 看 status=22（配置语法错误，多为 5.x 旧语法残留） |
| 插件报 failed to load | 6.0 中旧算法插件（aes/sha2/gmp 等）不存在属正常，openssl 后端已替代，可忽略 |

## 十三、版本差异（5.9 ↔ 6.0）

| 项目 | strongSwan 5.9（Ubuntu 24.04） | strongSwan 6.0（Debian 13） |
|---|---|---|
| 配置位置 | connection 内嵌 `eap_radius { servers {...} }`、`xauth_radius {...}` | connection 内 `remote { auth = eap-radius }`；服务器配置移到 `/etc/strongswan.d/charon/eap-radius.conf` |
| Cisco XAUTH | `remote { xauth = radius }` + `xauth_radius` 块（xauth-radius 插件） | **已移除**，xauth-radius 插件不存在 |
| IKEv1 | 支持 | 支持（但无 xauth-radius） |
| 算法后端 | gmp/aes/sha2 等自带插件 | openssl 插件后端（旧插件报 failed to load 属正常） |
| systemd 服务 | `strongswan-swanctl`（别名） | `strongswan.service`（`strongswan-swanctl` 是指向它的 alias，enable 别名会报 Refusing to operate on linked unit） |
| 证书引用 | `certs = gwCert.pem` | 同样支持任意文件名，建议直接用序列号命名 |

> Ubuntu 24.04 用户请将第六节 `remote { auth = eap-radius }` 保留，同时把第五节起的所有 `swanctl.conf` 里 connection 内的 `eap_radius`/`xauth_radius` 块移除，并同样使用 `/etc/strongswan.d/charon/eap-radius.conf`（5.9 也支持该插件级配置），可跨版本通用。
