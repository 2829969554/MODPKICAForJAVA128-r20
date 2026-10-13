# MODPKICA Java 复刻版 v1.28-r20（BC 1.85 离线）

> 用 **Java + BouncyCastle 1.85** 离线复刻 Go 版 MODPKICA 全套 PKI 功能，并在其上扩展了**完整的手机 VPN 认证链路**：X.509 证书签发、CRL 吊销列表、OCSP 在线状态、RFC 3161 / Authenticode 时间戳、RFC 6962 CT 日志（SCT 服务）、EXE/PDF 代码签名、WebAdmin 浏览器管理面板、**RADIUS 认证服务（12 种认证方式，含 EAP-TLS 证书登录）**、**PPPoE 接入服务**。
>
> - **技术栈**：纯 `javac` 编译，无 Maven / Gradle，无网络依赖，离线可开发
> - **依赖**：`BC185/` 目录下 BouncyCastle 1.85 全家桶（bcprov / bcpkix / bcutil / bcmail / bctls）+ `lib/`（pdfbox-app-3.0.4.jar）
> - **平台**：Windows（build.cmd）/ Linux（build.sh）
> - **当前版本**：`v1.28-r20`（2026-10-13）——EAP-TLS 重传「事务化」，修 iOS/Windows 证书登录死循环；完整历史见 [CHANGELOG.md](CHANGELOG.md)
> - **作者**：@魔帝本尊（QQ：2829969554）
>
> **本版重点（r20）**：安卓 strongSwan App 用证书登录一直正常，但 iPhone 原生 IKEv2（鉴定方式"证书"）与 Windows 自带 VPN 证书登录失败——RADIUS 日志**无限重复** `[iOS兼容] EAP-TLS 检测到网关重传…`，网关日志同一秒 25 条 IKE_AUTH 往返、约 12 秒后 `deleting half open IKE_SA … after timeout`（Windows 侧提示"在连接完成前，连接被远程计算机终止"）。根因是 r17 那套"重传重发上次响应"记的是**最近一次响应体**（分片拉取阶段那是末片）→ 客户端永远解析不出 ServerHello。现已改为**按事务重放**（入包 EAP-Id + 数据指纹 → 当时的 EAP-Id + 响应快照 + 片内偏移），并补上"重传拉取片不再跳片""客户端重启握手重建会话"两条路径，`EapTlsCertSmoke` 完整握手 EAP-Success + 64B MSK 导出、`IosEapTlsRetransmit` 新增 [7]/[8] 用例与 126 项单元测试全部通过。详见 [CHANGELOG.md](CHANGELOG.md#更新记录)。

---

## 目录

- [一、界面截图](#一界面截图)
- [二、功能特性](#二功能特性)
- [三、项目结构与源码类一览](#三项目结构与源码类一览)
- [四、环境要求与一键编译](#四环境要求与一键编译)
- [五、运行方式与命令行用法](#五运行方式与命令行用法)
- [六、WebAdmin 管理面板](#六webadmin-管理面板)
- [七、PKI 目录与全部配置文件（详解）](#七pki-目录与全部配置文件详解)
- [八、证书类型与命名规则](#八证书类型与命名规则)
- [九、VPN 网关接入（strongSwan）](#九vpn-网关接入strongswan)
- [十、常见问题 FAQ](#十常见问题-faq)
- [十一、更新记录](#十一更新记录)
- [十二、许可](#十二许可)

---

## 一、界面截图

### 仪表盘（证书链树 + 服务状态）

根 R → 中间 CA C → 终端 E 的证书链树，节点悬停显示证书参数；顶部一键刷新全部 CRL / 签发全部 OCSP / 签发全部时间戳；底部最近日志。

![仪表盘](a.png)

### 证书查看器（仿制 Windows 证书查看器）

**完全仿制 Windows 系统"证书"查看器对话框**——Windows 风格窗口（可拖拽移动、✕ 关闭），三页签布局与系统原版一致：

- **常规**：大证书图标 + 状态条（自动判定：不在有效期内显示琥珀色"已过期"；有效期内异步查询本库吊销状态，正常=绿色"该证书没有问题"，吊销=红色"该证书已被证书颁发机构吊销"）、"证书的目的"（EKU OID 全量中文对照，含证书策略特殊 OID「所有应用策略 / 所有颁发策略」）、颁发给 / 颁发者 / 有效期，底部「颁发者说明(S)」按钮——当证书策略含 CPS 链接或用户通告（Explicit Text）时自动出现，点击弹出说明窗（CPS 可点击外链 + 通告文本）；无证书策略则按钮自动隐藏
- **详细信息**：版本 / 序列号 / 签名算法（OID 正确命名，如 `SM2withSM3`、SHA256withRSA）/ 签名哈希算法 / 颁发者 / 有效期 / 使用者 / 公钥（**密钥类型 + 完整 HEX 字节流，16 字节一行**）；下拉过滤（全部 / 基本字段 / 扩展字段 / 关键字段）；扩展逐项展开——EKU（OID 中文对照）、AIA（OCSP + 颁发者 URL）、CRL 分发点、证书策略（CPS + User Notice）、密钥用法、SCT 列表（逐条：日志版本 / 日志名称 / 完整日志标识符 / 时间戳 / 签名类型 / 签名 / 验签状态）
- **证书路径**：树状信任路径（根→中间→终端），双击任意层级打开**独立新查看器**（路径自动截断到该层并默认选中）；底部显示当前层证书概要

入口：证书库每行「详情」→ JSON 结构弹窗 →「查看证书」按钮；证书库行**双击**直接打开。cacerts 公网证书库打开时只判有效期、不查吊销（无本库记录）。

![证书查看器](certview.png)

### 证书库（选择夹：证书库 CERTS.txt / 可信公网证书库 cacerts）

**「证书库 CERTS.txt」页**：序列号 / 类型 / 状态 / 原因 / 时间 / 颁发者 ID / 算法 / 操作，支持筛选与刷新；类型中文显示（R=根证书 / C=CA证书 / E=终端证书），状态三色（V 正常绿 / R 已吊销深红 / N 未知橙）；序列号与颁发者序列号悬停显示证书简要信息；每行含详情 / 验证 / 操作三个按钮（验证弹窗按状态显示绿/红/橙标题）；行**鼠标右键**弹出「下载证书 / 导出证书 / 删除证书」菜单——下载含单证书、证书链（crt/p7b）、私钥、pfx/jks 密钥库；导出含 PEM / HEX / Base64 剪贴板复制；**删除证书**经二次确认后**不删除文件**，只在 CERTS.txt 中为该行加 `#` 注释（忽略此行数据），生成 CRL / OCSP 证书时自动跳过。

**「可信公网证书库 cacerts」页**：读取 JAVA 环境 `cacerts`（JKS 信任库）全部证书，列表列 = 序列号 / 算法 / 生效日期 / 失效日期 / DN字段（时间格式 `yyyy/MM/dd HH:mm:ss`，序列号列收窄超长省略）；点击「详情」从 cacerts 导出 PEM 并转 JSON 结构化弹窗展示（X509JsonConverter 解析）。

![证书库](b.png)

### 签发根证书（MakeRoot + DN 辅助输入）

证书 DN（key=value 逗号分隔，key 可为标准属性或 OID）+ 密钥算法（RSA / ECC / SM2 下拉）+ 哈希算法 + 密钥位数（RSA 可编辑 1024~8192，ECC 只读 256/384/521，SM2 只读 256）；**DN 辅助输入**：通用名称 / 组织 / 组织单位 / 国家 / 省州 / 城市 / 邮箱各字段独立编辑框（placeholder 中文说明 + 例子），「是否 EV 扩展验证」勾选后显示 EV 注册字段，「+ 添加自定义字段」「从上方 DN 解析回填」双向同步；生成证书时 DN 按 X.500/RFC 规范顺序统一排序（C→ST→L→STREET→PostalCode→O→OU→SERIALNUMBER→CN，EV 字段随后）。

![签发根证书](c.png)

### 证书操作（吊销 / 续签 / 密钥更换）

证书库每行「操作」按钮弹出窗口，默认「吊销证书」分组：序列号可输入或下拉选择，显示证书简要信息（类型 / 序列号 / DN / 密钥对 / 哈希 / 长度 / OCSP 状态 / CRL 状态），选择吊销理由后确认吊销，或「恢复证书」将状态 R→V、原因置 0 并同步生成 CRL；另有「续签证书」（选择生效 / 失效时间重签）与「密钥更换」（按原算法生成新密钥对测试后重签，SKI 随新公钥更新）分组。

![证书操作](h.png)

### 证书链详情（悬停悬浮窗）

证书链树节点悬停弹出详情：证书类型（含策略识别）、序列号、DN、密钥对 / 哈希 / 密钥长度、OCSP 状态、CRL 状态。

![证书链详情](e.png)

### 调试专区（模拟 OCSP / 时间戳请求）

按标准协议构造请求并 POST 本机 MAIN，日志逐步展示：模拟 OCSP 请求（RFC 6960，CertID 基于真正颁发者证书 + Nonce，哈希算法可选 SHA1/SHA256/SHA384/SHA512/SM3，验证响应签名与 Nonce 回显）；模拟时间戳请求（RFC 3161，随机 32 字节 → 按所选摘要算法计算 messageImprint → TimeStampReq（Nonce + certReq）→ 解析 TimeStampResp 并验证 token 签名）。

![调试专区](g.png)

### 签名专区（选择夹：微软代码签名 / PDF 文档签名）

**选择夹布局**：签名专区改为上下两个独立页签（tab）——「微软代码签名」与「PDF 文档签名」各占整页，空间更大、互不干扰；全局字体 15px，控件间距与列表行高同步放大。

**微软代码签名（Authenticode）**：**同样支持批量选择与拖拽添加**——把 exe / dll / sys / cab / cat / msi 文件拖入虚线拖拽区或点击「选择文件」多选；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），行内可单独签名、验证、移除，成功后行内下载；顶部「批量签名」「批量验证」「清空」一次处理全部。签名支持 RSA / ECC / SM2（摘要分别 SHA256 / SHA256 / SM3），证书表按 Microsoft PE/COFF 规范嵌入。**时间戳类型**下拉可选 **RFC3161**（标准 TimeStampToken）或 **Authenticode**（老式 PKCS#7）；**时间戳请求地址**可编辑下拉留空 = 本机 MAIN，或指向 DigiCert / Symantec / Comodo / Certum 等外部 TSA。

**PDF 文档签名**：**支持批量选择（多选文件）与拖拽添加**——把 PDF 文件直接拖入虚线拖拽区，或点击「选择 PDF 文件」多选；待签名列表逐行显示文件名 / 大小 / 状态（待处理 / 签名中 / 成功 / 失败），每行可单独签名、验证、移除，成功后可下载；顶部「批量签名」「批量验证」「清空」一次处理全部。证书（带文档签名 EKU，微软 OID `1.3.6.1.4.1.311.10.3.12` 或通用 OID `1.3.6.1.5.5.7.3.36` 任一即可；**证书留空 = 纯文档时间戳，不签名**）。**签章类型**下拉四种：Adobe 标准文档签名（`adbe.pkcs7.detached`，RSA/ECC/SM2 均可，可选签章图片生成可见签章；**选中证书时时间戳按 CAdES-T / PAdES-T 标准嵌入签名内部（SignerInfo 的 unsignedAttrs 属性 id-aa-timeStampToken，messageImprint = SHA-256(签名值)），DSS/LTV 数据（证书链 + OCSP 响应 + CRL）与签名同一次保存、被签名覆盖，签名后零增量**；不选证书时生成独立 DocTimeStamp（ETSI.RFC3161）纯文档时间戳，同样带 DSS/LTV）；国密 GB/T 35275-2017（`GM.sm2cms.detached`，仅 SM2 证书 + 签章图；同样支持 CAdES-T 签名时间戳（SM3 摘要 + unsignedAttrs）与 DSS/LTV 同保存）；国密 GB/T 38540-2020（`GM.sm2seal` SES_Signature，仅 SM2 证书 + 签章图；按标准 7.1.6 支持嵌入时间戳——SES_Signature 可选第 5 字段 timeStamp（对签名值的时间戳，符合 GB/T 20520= RFC3161，DER 编码，SM3 messageImprint），并支持 DSS/LTV 同保存）；国密 GM/T 0031-2025（`GM.sm2seal`，仅 SM2 证书 + 签章图，数据结构与 38540 一致）。验证支持三种类型：CMS 验签 / 文档摘要比对 / 证书链（Adobe 与 35275），SES_Signature 专用解析（dataHash 比对 + SM2 验签，自动判别 38540 四/五字段、0031 两字段；38540 时间戳字段 timeStamp 解析：TSA/时间/算法/绑定签名值（SM3）+ TSA 证书验签）；Adobe 模式逐签名字段验证（数字签名含签名时间戳 CAdES-T unsignedAttrs 解析：TSA/时间/算法/绑定签名值，哈希算法自适应 SHA-256/SM3；DocTimeStamp 走 TimeStampToken 专用解析：messageImprint 比对 + TSA 证书验签），输出含 LTV 状态（DSS Certs/OCSPs/CRLs 数量）。

![签名专区选择夹](f.png)

### 签发证书（EV 扩展验证辅助输入）

证书 DN 辅助输入：CN / O / OU / C / S / L / E 邮箱基础字段 + 「是否 EV 扩展验证」勾选后显示 **EV 注册字段区**（注册类型 businessCategory 四选一：Private Organization / Government Entity / Business Entity / Non-Commercial Entity、注册号 serialNumber、组织标识符 organizationIdentifier、注册国家 / 注册省 / 注册市 jurisdiction*、组织标识符扩展 OID 版本新旧选择）；「密钥与算法」分组：证书类型（根证书 / CA证书 / 终端证书）、密钥算法、密钥位数、哈希算法；生成证书时 DN 按统一标准排序。

![签发证书](i.png)

### 签名专区（签章图片素材示例）

国密 PDF 电子签章（35275 / 38540 / 0031）需选择签章图片（png/jpg/bmp/gif），本图为内置示例签章 `stamp.png`（红色圆形电子签章：MODPKICA / 电子签章）。

![签章素材](stamp.png)

### SCT 服务管理（选择夹：CT日志密钥管理 / CT请求日志 / 可信公网CT公钥管理）

**CT日志密钥管理**：描述输入 + 生成 ECDSA / RSA / SM2 密钥对三按钮 + 刷新列表；密钥列表逐行显示 序号 / 描述 / 类型 / 日志公钥 ID（自适应列宽，超长省略）/ 状态（可用绿 / 不可用红）/ 创建时间 / 操作（「启用⇄暂停」单按钮点击切换 + 「删除」置末），密钥写入 `PKI/CTLOG/modpkica_ct_list.json`（v3 风格，`type` 字段区分 ECDSA/RSA/SM2，缺省 ECDSA）。

**CT请求日志**：只读展示 `PKI/CTLOG/ctlogs.txt` 全部行（自带序号）。

**可信公网CT公钥管理**：展示项目根 `log_list.json`（Google 权威 CT 日志公钥数据集 v3，`https://www.gstatic.com/ct/log_list/v3/log_list.json`）全部日志，含数据日期与「拉取最新数据」按钮（在线更新后刷新列表），布局参考密钥管理。

![SCT服务管理](j.png)

### 证书库（SCT 列表验签弹窗）

证书库「验证」按钮弹窗的 SCT列表 区块：逐条显示 日志版本 / 日志名称 / 日志标识符 / 时间戳 / 签名类型 / 签名 / 状态（签名有效 / 签名无效 / 未知日志，无法验证）——SM2 证书的 SCT 由 SM2 日志密钥签名（SM2-SM3），状态显示"签名有效"。

![SCT验签弹窗](k.png)

### 操作日志（logs.log 可视化）

时间范围筛选（最近 1/6/12/24 小时、全部）、行数设置、自动刷新（3 秒）、手动刷新；每条日志含时间、时间戳、操作、命令、结果。

![操作日志](d.png)

---

## 二、功能特性

### 1. MAIN —— 网络服务主程序

- **OCSP 在线证书状态协议**：`/OCSP`、`/ocsp`（POST），按请求证书序列号查 CERTS.txt 返回正常 / 已吊销 / 未知状态；支持 Nonce、按请求摘要算法自适应（SHA1/SHA256/SHA384/SHA512，SM2 固定 SM3，无摘要默认 SHA1）；未知序列号返回无签名 unauthorized 响应；用 `序列号_ocsp.crt/.key` 签署响应；SM2 分支吊销响应按 RFC 6960 标准编码（`revoked [1] IMPLICIT RevokedInfo`），openssl / BC 均可正常解析
- **CRL 吊销列表下载**：`/CRL/序列号.crl`、`/CRL/序列号.der.crl`
- **证书下载**：`/CRT/序列号.crt`
- **RFC3161 时间戳**：`/rfc3161`（文档签名专用，SHA1 / SHA256 自适应）
- **微软 Authenticode 时间戳**：`/timestamp`（SHA256）、`/timestamp/sha1`（SHA1）；请求体为 base64（容忍 CRLF / 末尾 NUL 等杂字符），响应为 PKCS#7 分离签名（eContent + signedAttrs 含 id-data 属性）
- **自适应根 TSA**：SHA1 → 随机 `rsa_sha1` / `ecc_sha1`；SHA256 → 随机 `rsa_sha256` / `ecc_sha256`；SM3/SM2 → `sm2_sm3`
- **CT 日志服务（RFC 6962）**：`/ct/add`（仅 POST），请求体为「PEM 预证书 + PEM 颁发者证书」，按 RFC 6962 §3.1 构造 precert_entry（issuer_key_hash + 去 poison TBS）→ 加载 `PKI/CTLOG/modpkica_ct_list.json` 中 usable 密钥签名 → 返回二进制 SCTList TLS 编码；**类型匹配选组**：SM2 预证书只选 usable 的 SM2 密钥，RSA/ECDSA 预证书只选 RSA+ECDSA 密钥，随机 ≤3 组（仅一组就签一组）；SCT 枚举 SM2=(7,4)（国密 CT 实现枚举，对齐零信 sm2ct.cn），ECDSA=(4,3)，RSA=(4,1)；每密钥一行追加 `PKI/CTLOG/ctlogs.txt`（`SCT待签名摘要||时间戳||终端SKI||终端AKI||日志公钥ID`）
- **静态网页**：`/` 提供 `PKI/WebPublic` 下文件
- **启动时自动刷新全部 CRL**
- **内嵌 WebAdmin 管理面板**；`RADIUSAUTO=on` / `PPPOEAUTO=on` 时随服务自动启动 RADIUS / PPPoE

### 2. Admin —— 管理控制台（命令行）

`init` 初始化环境、`makeroot` 签发根证书、`list` 列出证书、`signcert` 签发证书、`revoke` 吊销证书、`signCRL` 刷新 CRL、`initOCSP` 签发全部 OCSP 证书、`initTIMESTAMP` 签发全部时间戳证书、`verifyCERT` 证书验证。

### 3. MakeRoot —— 签发根证书

生成 `ROOT/序列号.crt`、`ROOT/序列号.key`，同步 `WebPublic/CRT/序列号.crt`，登记 CERTS.txt（类型 R）。

### 4. MakeCert —— 签发下级证书

支持签发中间 CA（类型 C）、终端证书（类型 E）；颁发者证书类型自动从 ROOT / CA 目录加载密钥对；支持 RSA / ECC / SM2 / PQC（ML-DSA-44/65/87，纯签名哈希 NULL）、SHA1 / SHA256 / SHA384 / SHA512 / SM3；密钥用法、增强型密钥用法（EKU 编号或 OID）、证书策略、SAN、有效期自定义。**SCT 预证书流程**：签发服务器 / 客户端证书（EKU 含服务器/客户端认证）时，先签发含 poison 扩展（RFC 6962）的 SCT 预证书，POST 本机 `/ct/add` 获取 SCTList，嵌入 SCT 扩展（OID `1.3.6.1.4.1.11129.2.4.2`）二次签名生成最终证书（已移除自创 2.4.5 扩展）。

### 5. RootGetCrl —— 签发吊销列表

遍历 CERTS.txt 中全部 R / C 证书，为每个颁发者生成独立 CRL（`WebPublic/CRL/序列号.crl`），哈希算法沿用颁发者证书（如 RSA/sha256、RSA/sha512）。

### 6. CertVerify —— 证书验证

输入证书文件或序列号，打印证书全字段（版本、序列号、签名算法、DN、有效期、公钥、SKI/AKI、EKU、SAN、AIA、CRL 分发点、KeyUsage、基本约束、证书策略、扩展、SCT）、签名验证、证书链、CRL + OCSP 吊销状态、各类哈希。**SCT 列表逐条验签**（RFC 6962）：按 log_id 匹配日志公钥（本地 CTLOG 密钥库 + 权威 log_list.json），构造 precert_entry / x509_entry 待签名数据重算摘要，ECDSA（DER + 裸 r‖s 兼容）/ RSA / SM2（枚举 7,4 与 7,7 均支持）验签，输出 日志名称 / 日志标识符 / 时间戳 / 签名类型 / 状态（签名有效 / 签名无效 / 未知日志，无法验证）。

### 7. Auto —— 自动化命令

`init` 初始化环境、`revoke 序列号 原因` 吊销证书、`newcert 序列号 类型 状态 原因 时间 颁发者ID 算法` 手工登记。

### 8. RadiusServer —— RADIUS 认证服务（RFC 2865 / 2866 / 2869 / 3579）

UDP 认证端口（默认 1812）+ 计费端口（默认 1813）双线程；账号复用用户管理库（`PKI/USERS.txt`）；认证与计费请求/响应全部写入 `logs.log` 与内存环形日志（最近 500 条）。

**12 种认证方式（全部按 RFC 标准实现，服务端 + 客户端调试双端）**：

| # | 认证方式 | 标准依据 | 说明 |
|---|---|---|---|
| 1 | PAP | RFC 2865 §5.2 | 明文口令，`MD5(Secret+Authenticator)` 混淆 |
| 2 | CHAP | RFC 2865 §5.3 | 16B 挑战 + `MD5(ChapId‖密码‖挑战)` |
| 3 | MS-CHAPv1 | RFC 2433 | Vendor-Specific(微软, Type=24)，MD4 NT-Hash 2×DES 加密挑战比对 |
| 4 | MS-CHAPv2 | RFC 2759 | 8B 挑战 + 50B 响应（Ident+Pad+PeerChallenge16+Reserved8+NT-Response24），服务端单包携带挑战+响应 |
| 5 | EAP-MD5 | RFC 3748 §5.4 | 16B 挑战，`MD5(InnerId‖密码‖挑战)` |
| 6 | EAP-GTC | RFC 3748 §5.6 | 明文令牌挑战（"Enter Password:" 提示），常数时间比对 |
| 7 | EAP-TLS | RFC 5216 | BC 1.85 `bctls` TLS 1.2 完整握手；RFC 5216 §2.1 1100B 分片每片一个 EAP 包；RFC 3579 §2.1 EAP-Message 属性切分拼接；TLS 1.2 签名 PKCS#1 v1.5；握手完成后按 RFC 5216 §2.4 手工导出 64B MSK 并经 **MS-MPPE-Recv/Send-Key 32+32B** 随 Access-Accept 下发（RFC 2548 §2.4.3）——**手机 strongSwan / iOS / Windows / 安卓 证书登录实测链路**；**EAP 层重传检测（RFC 3748 §5.1，v1.28-r20 事务化）**见下 |
| 8 | EAP-TTLS | RFC 5281 | 外层 TLS 隧道 + **内层 PAP AVP 交换**（RFC 5281 §8.5：Type(1)+Length(1)+Value，User-Name/User-Password） |
| 9 | PEAP-MD5 | RFC 5216 隧道 + 内层 EAP-MD5 | 外层 PEAP Start→TLS 隧道→内层 MD5 挑战/响应 |
| 10 | PEAP-MSCHAPv2 | RFC 5216 + RFC 2759 | 内层 MS-CHAPv2 两轮隧道交换（Challenge→NT-Response 50B） |
| 11 | PEAP-GTC | RFC 5216 隧道 + RFC 3748 §5.6 | 内层 GTC 明文令牌 |
| 12 | EAP-pwd | RFC 5931（P-256） | 四轮密钥交换：ID(Group=6)→Commit(标量32B+SEC1 压缩点33B)→双向 Confirm(HMAC-SHA256)→Success；猎取-啄食法 PWE 派生（HKDF-SHA256，p≡3 mod 4 开根） |

**EAP-TLS 重传「事务化」（v1.28-r20，网关重传 / 客户端重启三连修）**：

- **重放按事务**：记录 `(入包 EAP-Id + 数据指纹) → (当时下发的 EAP-Id + 响应快照 + 片内偏移)`（会话维度最近 8 笔、src 维度最近 1 笔）。命中重传即以**同一 EAP-Identifier** 重放**该笔**响应，分片按 (快照, 偏移) 逐字节重建并回绕游标——**首片仍是首片**（旧实现记"最近一次响应体"，拉片阶段那是末片，客户端永远解析不出 ServerHello → 无限循环）。
- **空拉取片纳入判定**：1B `0x00` 的重复拉取＝IKE 层重传 → 回放上一片（旧实现当作新拉取直接前进 → 跳过一片 → 客户端飞行残缺）。服务端 Request Identifier 按 RFC 3748 §4.1 **自增**（不再回显客户端 Id），回显型客户端每次拉取自然携带新 Id、重传携带旧 Id，两者可精确区分。
- **客户端重启可恢复**：握手推进中（已喂过客户端 TLS 记录）收到**新的**完整 ClientHello → 判为客户端重开握手，丢弃旧会话（含其握手线程）并重建，把该 ClientHello 作为新会话首个输入（旧实现喂给旧状态机 → `unexpected_message(10)` → 立即 alert + EAP-Failure，客户端重启一次就被判死）。
- 日志标记：`[iOS兼容] EAP-TLS 检测到网关重传…（scope=src/会话，快照 NNNNB，片偏移 N）`、`[iOS兼容] EAP-TLS 客户端重启握手…→ 重建会话`。

**EAP 会话密钥（MSK）下发**：

- **EAP-MSCHAPv2**：认证通过后 Access-Accept 自动携带 **MS-MPPE-Recv-Key(type17)/MS-MPPE-Send-Key(type16)**（RFC 2548 §2.4.3 加密 + §2.4.2 语义）——密钥按 RFC 3079 §3.1 由 `SHA1(MD4(NT-Hash)‖NT-Response‖MPPE 魔数)` 派生（magic2=客户端 send / 服务器 receive、magic3=客户端 recv / 服务器 send），**16+16 字节**；strongSwan `eap-radius` 网关解密后重组 `recv‖send‖补零 64B` 即得到与客户端完全一致的 64 字节 EAP MSK（RFC 5247），**IKEv2（手机 strongSwan）+ PEAP + TTLS 会话密钥链路实测打通**
- **EAP-TLS**：握手线程 `proto.accept()` 返回后按 RFC 5216 §2.4 导出 `MSK = PRF(master_secret,"client EAP encryption",client_random‖server_random)[0..63]`（BC 1.85 无公开 exporter 且 RFC 5705 exporter 强制要求 EMS——strongSwan 不支持已关闭，故用 TLS 1.2 `P_SHA256` 手工实现；master secret 三级获取：`SecurityParameters.getMasterSecret()` → 反射 `TlsProtocol.sessionMasterSecret` → `SessionParameters.getMasterSecret()`）；Access-Accept 按 RFC 2548 §2.4.3 下发 **MS-MPPE-Recv-Key = MSK[0..32) / MS-MPPE-Send-Key = MSK[32..64)（32+32 字节）**，strongSwan 网关据此恢复 64B MSK 完成 IKEv2 AUTH（RFC 7296 §2.16）——**服务端/客户端 MSK 64B 逐字节一致（实测）**

属性布局与 strongSwan `radius_socket.decrypt_msk` 的 `mppe_key_t` 逐字节对齐（`Vendor-ID(311)‖Type‖Length‖Salt‖Cipher`，Length=4+N，加密种子=对应 Access-Request 的 Request-Authenticator，RFC 2548 §2.4.3 MD5 链式）。

**EAP-TLS 服务器证书来源**：`PKI/CERT/{序列号}.crt`（要求 EKU 含 serverAuth，私钥取 `PKI/KEY/{序列号}.key`，链按 issuer DN 从 `PKI/CA`、`PKI/ROOT` 组装）；`CONFIG.txt` 的 **`RADIUSCERT=序列号`** 可显式指定，未指定时按文件名排序自动选择第一张有配对私钥的证书。

**属性支持**：`User-Name` / `User-Password` / `CHAP-Password`+`CHAP-Challenge` / `NAS-*`；**Vendor-Specific（微软，RFC 2548）**：MS-CHAP-Challenge / MS-CHAP-Response / MS-CHAP2-Response（按 Vendor-Type 自动分流 v1/v2）；**MS-MPPE-Send/Recv-Key（type16/17，会话密钥下发）**；**隧道属性（RFC 2867/2868）**：Tunnel-Type / Tunnel-Medium-Type / Tunnel-Client-Server-Endpoint / Tunnel-Password 自动解析成文字记录（PPTP/L2TP/IPsec/GRE 场景可见）；`Message-Authenticator`（RFC 2869 §5.3，HMAC-MD5，**EAP 请求必须携带，缺失一律 Reject**）；`EAP-Message`（RFC 3579 §2.1，>253B 自动切分、响应端按出现顺序拼接还原）。

**Identity 用户名前缀分流**（大小写不敏感，顺序固定）：`ttls:`/`eap-ttls:`→TTLS；`pwd:`/`eap-pwd:`→EAP-pwd；`gtc:`/`eap-gtc:`→EAP-GTC；`peap-gtc:`/`eap-peap-gtc:`→PEAP-GTC；`peap-mschapv2:`/`eap-peap-mschapv2:`→PEAP-MSCHAPv2；`peap:`/`eap-peap:`→PEAP-MD5；`tls:`/`eap-tls:`→EAP-TLS；无前缀→PAP/CHAP/MS-CHAPv1/MS-CHAPv2（自适应：先发 EAP-MSCHAPv2，客户端 NAK 声明 EAP-TLS 时自动切换证书认证）。

**客户端-调试专区**：WebAdmin「Radius服务管理」页含「服务管理 / 客户端-调试专区」双分类夹——调试专区可选任意一种认证方式（12 项下拉）+ 账号/密码/共享密钥/端口，`发起调试` 后逐步打印完整握手过程（含每步 EAP 报文、TLS 分片、AVP 帧、EAP-pwd 标量/元素/Confirm 值），结果写入 `logs.log`。

### 9. PPPoEServer —— PPPoE 接入服务（RFC 2516 + RFC 1661 + RFC 1334 + RFC 1994）

UDP 封装标准报文：Discovery `0x8863`（默认 512）+ Session `0x8864`（默认 513）。

- **Discovery 阶段（RFC 2516）**：PADI(0x09)→PADO(0x07)/PADR(0x19)→PADS(0x65)/PADT(0xa7)；标签 Service-Name(0x0101)/AC-Name(0x0102)/Host-Uniq(0x0103)
- **Session 阶段（RFC 1661 PPP LCP）**：Conf-Req/ACK/NAK/REJ/Term-Req/Ack；选项 MRU / Auth-Protocol / Magic-Number
- **PPP 认证**：PAP（RFC 1334）+ CHAP（RFC 1994，`MD5(Id‖密码‖挑战)`）
- 认证复用用户管理库；WebAdmin「PPPoE服务管理」页提供完整拨号流程模拟（PADI→PADO→PADR→PADS→LCP→PAP/CHAP→PADT）

### 10. WebAdmin —— 浏览器管理面板

深色主题管理后台（**18 个页面 / 71 个 API**），详见[第六节](#六webadmin-管理面板)。

---

## 三、项目结构与源码类一览

```
modpkica4JAVA/
├── BC185/                        # BouncyCastle 1.85 离线 jar 全家桶
├── lib/                          # pdfbox-app-3.0.4.jar（PDF 签名/验证）
├── src/modpkica/                 # 全部源码（26 个类）
├── out/                          # 编译输出（javac -d out）
├── build.cmd / build.sh          # Windows / Linux 一键编译脚本（可带 1-9 编号自动运行）
├── debug_test/                   # 冒烟测试与协议调试工具（见下）
│   ├── ModpkicaUnitTest.java     # 126 项单元测试
│   ├── RadiusSmokeTest.java      # RADIUS 5 项（PAP/CHAP/EAP-MSCHAPv2/计费/MA 校验）
│   ├── OcspSmokeTest.java        # OCSP 3 项
│   ├── EapTlsCertSmoke.java      # EAP-TLS 证书登录全链路冒烟（真实走 UDP 1812）
│   ├── IosEapTlsRetransmit.java  # iOS 网关重传复现 / 事务化重放回归（含 [7][8] 用例）
│   └── tools/eaptls_verify.py    # EAP-TLS 抓包 + SKE 签名手工验签（python）
├── linux/
│   ├── install_strongswan.sh     # 网关一键部署脚本（见第九节）
│   └── debian13/                 # Debian 13 网关配置快照（swanctl.conf 等，供对照）
├── PKI/                          # 运行时数据目录（MODPKICA_BASE 指向项目根时）
│   ├── ROOT/ CA/ CERT/ KEY/      # 证书与私钥（类型 R / C / E）
│   ├── OCSP/ TIMSTAMP/           # OCSP 签名证书 / TSA 证书
│   ├── CTLOG/                    # CT 日志密钥库 + 请求日志
│   ├── WebPublic/{CRT,CRL}/      # 对外下载目录
│   ├── CERTS.txt CONFIG.txt USERS.txt logs.log
├── a.png ~ k.png, certview.png, stamp.png   # 界面截图（本文档配图）
├── README.md                     # 本文件（项目总览 / 全部配置文件详解）
├── CHANGELOG.md                  # 完整更新记录（v1.0 → 至今）
├── strongSwan接入指南.md          # 网关部署 + 客户端拨号 + 故障排查
└── 开发助手_源码分析20261002.pdf  # 源码结构 / 运行流程 / 常量函数速查
```

### 源码类一览（src/modpkica/）

| 类 | 职责 |
|---|---|
| `MAIN` | 主程序 1：HTTP 服务（OCSP / CRL / 时间戳 / 静态网页）+ 内嵌 WebAdmin + 按配置自动启动 RADIUS/PPPoE |
| `Admin` | 主程序 2：管理控制台（doInit / doMakeRoot / doSignCert / doRevoke / doSignCrl / doInitOcsp / doInitTimestamp / doVerifyCert / doList）；`Admin.VERSION` 为版本号（与 README / CHANGELOG 对齐） |
| `MakeRoot` | 主程序 3：签发根证书 |
| `MakeCert` | 主程序 4：签发下级证书（CA / 终端） |
| `RootGetCrl` | 主程序 5：生成全部 CRL |
| `CertVerify` | 主程序 6：证书验证（详情 / 签名 / 链 / 吊销 / 哈希） |
| `Auto` | 主程序 7：自动化（init / revoke / newcert） |
| `WebAdmin` | 浏览器管理面板（默认 8080，15 页面 / 33 API） |
| `RadiusServer` | RADIUS 认证/计费服务（12 种认证方式 + EAP-TLS 事务化重传 + MSK/MS-MPPE 下发） |
| `PPPoEServer` | PPPoE Discovery/Session + PPP LCP/PAP/CHAP |
| `Bc` | BC Provider 注册 |
| `PemIO` | PEM 证书 / 私钥读写、密钥类型探测、原子写（tmp → fsync → .bak → move） |
| `CertUtil` | 证书构建工具（SKI、扩展组装、私钥读取、私钥/证书配对校验） |
| `CrlUtil` | CRL 生成 / DER→PEM |
| `OcspUtil` | OCSP 请求解析 / 响应生成（含 SM2、Nonce、无签名响应） |
| `TimestampUtil` | RFC3161 与 Authenticode 时间戳（含 SM2→SM3） |
| `Sm2Util` | 国密 SM2 签名 / 验签 / SM3 / ZA 计算 |
| `SignTool` | EXE / PDF 签名与验证（Authenticode 手工 ASN.1、RFC3161/Authenticode 时间戳、Adobe 与国密 PDF 电子签章、SES_Signature 验证） |
| `CtLog` | CT 日志密钥库 CRUD（ECDSA/RSA/SM2）、RFC 6962 预证书 SCT 签名、SCTList 编码、类型匹配选组（≤3 组） |
| `CertsDB` | CERTS.txt 登记表加载 / 查询 / 刷新（快照式整体替换，跨进程文件锁） |
| `UsersDB` | USERS.txt 用户库读写（E/D 状态、原子写 + .bak） |
| `Config` | CONFIG.txt 配置加载（大小写不敏感、`getRaw()` 返回全部键） |
| `MLog` | 追加式操作日志（时间 / 时间戳 / 操作 / 命令 / 结果） |
| `AppPaths` | 工作目录定位（环境变量 MODPKICA_BASE） |
| `AppEnv` | 可执行程序清单 |
| `X509JsonConverter` | X.509 证书 → JSON 结构化（证书库详情展示用） |

---

## 四、环境要求与一键编译

| 项目 | 要求 |
|---|---|
| JDK | 17+（JDK 17/21/26 均可），`javac` / `java` 在 PATH 中 |
| 依赖 | 无需联网，`BC185/`（BC 1.85 全家桶）+ `lib/`（pdfbox-app-3.0.4.jar） |
| 系统 | Windows 10/11 或 Linux（Debian/Ubuntu 等，脚本分别提供 .cmd / .sh） |

### Windows

双击 `build.cmd`，或在 cmd 中执行：

```bat
build.cmd          :: 只编译
build.cmd 1        :: 编译成功后自动运行 MAIN
```

脚本流程：检查 javac → 清理 `out/` → `javac -Xlint:all -encoding UTF-8 -cp "BC185\*;lib\*" -d out src\modpkica\*.java`（**零警告**）→ 校验 8 个 class（7 个主程序 + WebAdmin）→ 成功才打印运行命令提示。

**编号参数（编译后自动运行）**：

| 编号 | 自动运行的命令（等价于手敲 java 命令） |
|---|---|
| `1` | `java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MAIN`（MAIN 服务 + WebAdmin 面板） |
| `2` | `java ... modpkica.WebAdmin`（只开管理面板） |
| `3` | `java ... modpkica.Admin`（交互式管理控制台） |
| `4` | `java ... modpkica.MakeRoot "CN=Root,O=Org,C=CN" 2048 sha256 RSA`（签发根证书**示例参数**） |
| `5` | `java ... modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null ROOTSERIAL RSA`（签发证书**示例参数**） |
| `6` | `java ... modpkica.RootGetCrl`（刷新全部 CRL） |
| `7` | `java ... modpkica.CertVerify cert.crt`（验证**示例文件** cert.crt） |
| `8` | `java ... modpkica.Auto revoke 1234567890 1`（吊销**示例序列号**） |
| `9` | `ModpkicaUnitTest`（单元测试：先编译 `debug_test\ModpkicaUnitTest.java`，编译失败则不运行） |

> **注意**：编号 4/5/7/8 自动运行的是脚本内置的**固定示例参数**，不会透传额外参数；实际业务参数请改脚本 `:run_4`~`:run_8` 段落，或直接手敲完整 `java` 命令。

### Linux

```bash
chmod +x build.sh
./build.sh        # 只编译（javac -Xlint:all 零警告；脚本已用 LF 行尾）
./build.sh 1      # 编译成功后自动运行 MAIN（编号 1-9，与 build.cmd 完全一致）
```

**调试测试**（需先 `./build.sh`）：

```bash
java -cp "out;debug_test/classes;BC185/*;lib/*" ModpkicaUnitTest      # 126 项
java -cp "out;debug_test/classes;BC185/*;lib/*" modpkica.RadiusSmokeTest
java -cp "out;debug_test/classes;BC185/*;lib/*" modpkica.OcspSmokeTest
java -cp "out;debug_test/classes;BC185/*;lib/*" EapTlsCertSmoke        # 需 MAIN 已运行（真实 UDP 1812）
java -cp "out;debug_test/classes;BC185/*;lib/*" IosEapTlsRetransmit    # 同上
```

> 测试源码在 `debug_test/`，需先编译：`javac -encoding UTF-8 -cp "out;BC185/*;lib/*" -d debug_test/classes debug_test/*.java`

---

## 五、运行方式与命令行用法

所有主程序统一入口格式：

```bat
set MODPKICA_BASE=你的PKI根目录
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.主程序名 [参数...]
```

> **重要**：Windows 下必须加 `-Dfile.encoding=UTF-8`，否则中文日志 / 中文 DN 乱码（GBK 问题）。
> `MODPKICA_BASE` 缺省时取当前工作目录；示例环境为项目根（`PKI/` 直接位于其下）。

```bat
:: 运行 MAIN（推荐，WebAdmin 面板随服务自动启动）
set MODPKICA_BASE=C:\Users\28299\Desktop\modpkica4JAVA
java "-Dfile.encoding=UTF-8" -cp "out;BC185\*;lib\*" modpkica.MAIN
```

- WEB 服务端口：`PKI/CONFIG.txt` 的 `WEBPORT`（默认 80）
- WebAdmin 管理端口：`PKI/CONFIG.txt` 的 `SUPORT`（默认 8080）或系统属性 `-Dmodpkica.admin.port=8082`
- 浏览器访问 `http://localhost:8080`（管理面板）、`http://localhost:80`（WEB 服务）

### Admin（管理控制台，交互式）

| 命令 | 说明 |
|---|---|
| `init` | 初始化环境（清空证书目录 + 重建 CERTS.txt） |
| `makeroot 证书DN 密钥位数 哈希算法 密钥算法` | 签发根证书，如 `makeroot "CN=Root,O=My Org,C=CN" 2048 sha256 RSA` |
| `list` | 列出全部登记证书 |
| `signcert 证书DN 密钥位数 哈希算法 证书类型 有效期年数 SAN类型 SAN内容 颁发者序列号 密钥算法` | 签发下级证书 |
| `revoke 序列号 原因编号` | 吊销证书（原因 0-9，见 7.3 节） |
| `signCRL` | 刷新全部 CRL |
| `initOCSP 密钥算法 [序列号]` | 为全部（或指定）R/C 证书签发 OCSP 签名证书 |
| `initTIMESTAMP 哈希算法` | 签发时间戳证书（rsa/ecc/sm2 × sha1/sha256/sm3） |
| `verifyCERT 证书文件或序列号` | 证书验证 |

### 其余主程序

```bat
java ... modpkica.MakeRoot "CN=Root,O=My Org,C=CN" 2048 sha256 RSA
java ... modpkica.MakeCert "CN=www.test.com" 2048 sha256 1 1 0 1 "www.test.com" null null ROOTSERIAL RSA
java ... modpkica.RootGetCrl
java ... modpkica.CertVerify cert.crt          :: 按文件
java ... modpkica.CertVerify 113521bfd         :: 按序列号（自动去 WebPublic/CRT 查找）
java ... modpkica.Auto init
java ... modpkica.Auto revoke 113521bfd 5
java ... modpkica.Auto newcert 序列号 E V 0 null 13fbe86586d1bca RSA
```

> **MakeCert 参数顺序**（与 WebAdmin 签发证书页一致）：
> `证书DN 密钥位数 哈希算法 [1=终端证书] [1=KeyUsage digitalSignature...] [EKU位图] [1=写 SAN] "SAN内容" 颁发者序列号 [noAIA] 密钥算法`
> 网关证书推荐：`2048 sha256 1 1 0 1 "vpn.local" "服务器IP,127.0.0.1" noAIA 根序列号 RSA`（`noAIA` 不写 AIA/CRL 分发点，避免客户端去访问不可达的 localhost 吊销服务）。

---

## 六、WebAdmin 管理面板

启动 MAIN 或 WebAdmin 后，浏览器访问管理端口（默认 `http://localhost:8080`）。

### 页面（18 个）

| 页面 | 功能 |
|---|---|
| 仪表盘 | 服务状态、证书链树（R→C→E，悬停详情、R 展开 / C 收起管理下级）、一键刷新 CRL / 签发 OCSP / 签发时间戳、最近日志 |
| 证书库 | CERTS.txt 列表（类型中文、状态三色、筛选、刷新）、悬停悬浮窗、详情（JSON）、验证（三态 + SCT 逐条验签）、操作（吊销 / 续签 / 密钥更换）、右键下载（单证书 / 链 / 私钥 / pfx / jks）与导出（PEM/HEX/Base64） |
| 签发根证书 | 根证书参数表单 |
| 签发证书 | 完整参数表单（DN / 类型 / 密钥算法 / 密钥位数联动 / 哈希 / KeyUsage / EKU / 有效期 / SAN / EV 字段） |
| 吊销证书 | 按序列号 + 原因吊销 |
| CRL 刷新 | 重新生成全部 CRL |
| OCSP 签发 | 为全部 R/C 证书签发 OCSP 签名证书 |
| 时间戳签发 | 签发时间戳证书 |
| 证书验证 | 输入证书文件或序列号验证（证书策略识别含 SSL/代码签名/文档签名/TSA 等 OID；SCT 列表逐条验签） |
| 初始化环境 | 清空重建（不会执行重置类脚本，由 WEB 面板提供） |
| 系统配置 | 可视化读写 CONFIG.txt（WEBPORT / SUPORT / OCSP / CRL / CRT / CPS / CPS_Nonice 多行文本） |
| 操作日志 | logs.log 时间范围筛选 + 自动刷新 |
| 调试专区 | 模拟 OCSP 请求（RFC 6960）+ 模拟时间戳请求（RFC 3161），展示与验签全过程 |
| SCT服务管理 | CT日志密钥管理（ECDSA/RSA/SM2 生成 / 启用暂停 / 删除）+ CT请求日志 + 可信公网CT公钥管理 |
| 签名专区 | 微软代码签名（RFC3161/Authenticode 时间戳）+ PDF 文档签名（Adobe / 国密 35275 / 38540 / 0031） |
| 用户管理 | USERS.txt 用户库增删改（用户名 / 密码 / 状态启用停用 / 组 / 备注） |
| RADIUS 服务管理 | 服务开关 + 端口/密钥/自动启动配置 + **客户端-调试专区**（12 种认证方式逐步握手模拟） |
| PPPoE 服务管理 | 服务开关 + Discovery/Session 端口 + **客户端-调试专区**（完整拨号流程模拟） |

### API（71 个）

| 分类 | 接口 |
|---|---|
| 状态 / 列表 / 日志 | `/api/status`、`/api/version`、`/api/certs`、`/api/certs/cacerts`、`/api/certs/delete`、`/api/certjson`、`/api/certchainjson`、`/api/chain`、`/api/issuers`、`/api/logs`、`/api/config` |
| 证书下载 / 导出 | `/api/cert/download`、`/api/cert/export` |
| 签发 / 吊销 / 续期 | `/api/init`、`/api/makeroot`、`/api/signcert`、`/api/revoke`、`/api/restore`、`/api/rekey`、`/api/renew`、`/api/crl`、`/api/initocsp`、`/api/inittimestamp`、`/api/verify`、`/api/verify/file` |
| 代码 / PDF 签名 | `/api/signcerts`、`/api/sign/exe`、`/api/sign/pdf`、`/api/verify/exe`、`/api/verify/pdf` |
| 调试专区 | `/api/debug/ocsp`、`/api/debug/tsa` |
| CT 日志（SCT） | `/api/ctlog/list`、`/api/ctlog/logs`、`/api/ctlog/gen`、`/api/ctlog/delete`、`/api/ctlog/enable`、`/api/ctlog/pause`、`/api/ctlog/public`、`/api/ctlog/publicFetch`、`/api/ctlog/tree`、`/api/ctlog/samplechain`、`/api/ctlog/v1proxy` |
| 我的证书库 | `/api/my/list`、`/api/my/import`、`/api/my/delete` |
| 模板签名 | `/api/template/list`、`/api/template/save`、`/api/template/delete`、`/api/template/sign` |
| 用户管理 | `/api/users/list`、`/api/users/add`、`/api/users/update`、`/api/users/delete`、`/api/users/status` |
| RADIUS 服务 | `/api/radius/status`、`/api/radius/config`、`/api/radius/start`、`/api/radius/stop`、`/api/radius/reset`、`/api/radius/dial`、`/api/radius/logs`、`/api/radius/clearlogs` |
| PPPoE 服务 | `/api/pppoe/status`、`/api/pppoe/config`、`/api/pppoe/start`、`/api/pppoe/stop`、`/api/pppoe/reset`、`/api/pppoe/dial`、`/api/pppoe/logs`、`/api/pppoe/clearlogs` |

---

## 七、PKI 目录与全部配置文件（详解）

### 7.1 目录总览

| 路径 | 内容 |
|---|---|
| `PKI/ROOT/` | 根证书：`序列号.crt` + `序列号.key` |
| `PKI/CA/` | 中间证书：`序列号.crt` + `序列号.key` |
| `PKI/CERT/` | 终端证书 PEM：`序列号.crt`（**RADIUS EAP-TLS 服务器证书也取自这里**） |
| `PKI/KEY/` | 终端证书私钥：`序列号.key` |
| `PKI/OCSP/` | OCSP 签名证书：`序列号_ocsp.crt` + `序列号_ocsp.key` |
| `PKI/TIMSTAMP/` | TSA 证书：`类型_哈希算法.crt/.key`（rsa_sha1 / rsa_sha256 / ecc_sha1 / ecc_sha256 / sm2_sm3） |
| `PKI/CTLOG/` | `modpkica_ct_list.json`（CT 日志密钥库，v3 风格）+ `ctlogs.txt`（SCT 请求日志，只追加） |
| `PKI/WebPublic/CRT/` | 全部证书对外下载：`序列号.crt` |
| `PKI/WebPublic/CRL/` | 全部 CRL 对外下载：`序列号.crl`、`序列号.der.crl`（另有 `.bak` 原子写备份） |
| `PKI/CERTS.txt` | 证书登记表（见 7.3） |
| `PKI/CONFIG.txt` | 系统配置（见 7.2） |
| `PKI/USERS.txt` | RADIUS / PPPoE 用户库（见 7.4） |
| `PKI/logs.log` | 操作日志（见 7.5） |

### 7.2 `PKI/CONFIG.txt`（全部键）

无文件时由 MAIN / WebAdmin 自动创建默认模板；缺失的新键会被自动追加（不覆盖已有值）。`Config` 类加载时**大小写不敏感**、忽略 `#` 注释行与空行，`getRaw()` 可读取任意自定义键。

```ini
WEBPORT=80
SUPORT=8080
OCSP=http://localhost:80/OCSP
CRL=http://localhost:80/CRL/{CID}.crl
CRT=http://localhost:80/CRT/{CID}.crt
CPS=https://gitee.com/wxgshuju/modpkica
CPS_Nonice=http://example.com/nonice
CTLOGapi=/ct/v1/add-pre-chain
RADIUSPORT=1812
RADIUSACCT=1813
RADIUSKEY=mytestkey
RADIUSAUTO=on
RADIUSCERT=f7679b33352bd0d0e150e8594606c01f
PPPOEDISC=512
PPPOESESS=513
PPPOEAUTO=on
```

| 键 | 默认 | 含义 | 使用方 |
|---|---|---|---|
| `WEBPORT` | `80` | MAIN 的 HTTP 服务端口（OCSP / CRL / CRT / 时间戳 / 静态网页） | MAIN、SignTool（定位本机 TSA） |
| `SUPORT` | `8080` | WebAdmin 管理面板端口（也可用启动参数 `-Dmodpkica.admin.port=`） | WebAdmin |
| `OCSP` | `http://localhost:80/OCSP` | 写入证书 **AIA 的 OCSP 地址**；支持 `{CID}` 占位符 | MakeCert |
| `CRL` | `http://localhost:80/CRL/{CID}.crl` | 写入证书 **CRL 分发点**；`{CID}` = 颁发者序列号 | MakeCert |
| `CRT` | `http://localhost:80/CRT/{CID}.crt` | 写入证书 **AIA 颁发者证书地址**；`{CID}` = 颁发者序列号 | MakeCert |
| `CPS` | 项目仓库地址 | 证书策略 **CPS URI**（策略扩展 1.3.6.1.5.5.7.2.1） | MakeCert |
| `CPS_Nonice` | `http://example.com/nonice` | 证书策略 **用户通告（UserNotice）** 文本；面板多行输入，存储时换行写作 `\n` | MakeCert |
| `CTLOGapi` | `/ct/v1/add-pre-chain` | 签发证书时提交预证书的 CT 接口：`/ct/v1/add-pre-chain`（RFC 6962 §4 标准）或 `/ct/add`（本项目私有） | CtLog、MakeCert |
| `RADIUSPORT` | `1812` | RADIUS 认证端口 | MAIN、WebAdmin、RadiusServer |
| `RADIUSACCT` | `1813` | RADIUS 计费端口 | 同上 |
| `RADIUSKEY` | `mytestkey` | RADIUS 共享密钥（**必须与网关 `eap-radius.conf` 的 `secret` 一致**） | 同上 |
| `RADIUSAUTO` | `off`（面板勾选后写 `on`） | MAIN 启动时是否自动启动 RADIUS 服务 | MAIN |
| `RADIUSCERT` | 空 | EAP-TLS **服务器证书序列号**（`PKI/CERT/{序列号}.crt`，需 serverAuth EKU）；留空按文件名排序自动选第一张有配对私钥的证书 | RadiusServer |
| `PPPOEDISC` | `512` | PPPoE Discovery 端口（自定义 UDP 封装） | MAIN、WebAdmin、PPPoEServer |
| `PPPOESESS` | `513` | PPPoE Session 端口 | 同上 |
| `PPPOEAUTO` | `off` | MAIN 启动时是否自动启动 PPPoE 服务 | MAIN |

> **注意**：`OCSP` / `CRL` / `CRT` 里的 `localhost` 是**客户端视角**的地址。如果证书要被手机 / Windows 使用，且这些 URL 不可达，客户端验证时可能超时——**给 VPN 网关证书签发时建议加 `noAIA` 参数**（不写 AIA/CRL 分发点），详见《strongSwan接入指南》第四节。

### 7.3 `PKI/CERTS.txt`（证书登记表）

每行一条，空白分隔：

```
序列号 类型 状态 原因编号 签发/吊销时间 颁发者序列号 密钥算法
```

示例：

```
13fbe86586d1bca R V 0 2026/09/08-23:18:34 13fbe86586d1bca RSA
113521bfd E R 5 2026/09/09-00:53:25 1cdd332012fa2 RSA
f7679b33352bd0d0e150e8594606c01f E V 0 2026/10/09-20:21:10 7712d9352e6038ce78e57e3f572cec74 RSA
```

| 字段 | 取值 |
|---|---|
| 序列号 | 证书序列号（十六进制，小写，无前导 `0x`） |
| 类型 | `R` 根证书 / `C` 中间 CA / `E` 终端证书 |
| 状态 | `V` 正常（Valid）/ `R` 已吊销（Revoked）/ `N` 未知 |
| 原因编号 | 详见下表（吊销时写入，恢复时置 0） |
| 时间 | `yyyy/MM/dd-HH:mm:ss`（签发或吊销时刻） |
| 颁发者序列号 | 自签根证书填自身序列号 |
| 密钥算法 | `RSA` / `ECC` / `SM2` / `RSA-PSS` / `ML-DSA-44/65/87` 等 |

**吊销原因编号（与 WebAdmin 下拉、CRL Reason 对齐）**：

| 编号 | 含义 |
|---|---|
| 0 | 未指定（unspecified） |
| 1 | 密钥泄露（keyCompromise） |
| 2 | CA 泄露（cACompromise） |
| 3 | 从属关系变更（affiliationChanged） |
| 4 | 证书超期（superseded） |
| 5 | 停止运营（cessationOfOperation） |
| 6 | 证书吊销（certificateHold） |
| 8 | 从 CRL 移除（removeFromCRL） |
| 9 | 其他（privilegeWithdrawn / 自定义） |

> **行首 `#` = 忽略此行**（WebAdmin 右键「删除证书」即如此标记，**不删除文件**）：CRL 生成、OCSP 查询、时间戳处理、证书库列表均自动跳过（`CertsDB` 统一处理）。
> MAIN 在 OCSP / 时间戳 / RADIUS 处理前会重新加载 CERTS.txt，**外部修改即时生效、无需重启**。

### 7.4 `PKI/USERS.txt`（RADIUS / PPPoE 用户库）

文件格式（空白分隔；`#` 注释行与空行按原顺序保留）：

```
# MODPKICA RADIUS 用户库
# 字段顺序: 用户名 密码 状态 组 备注   (状态: E=启用 D=停用)
# 删除 = 行首加 # 注释（不真正删除）
admin888 admin888 E admin 管理员账号
alice 123456 E users 测试账号
```

| 字段 | 说明 |
|---|---|
| 用户名 | 登录名（RADIUS User-Name / EAP Identity / PPPoE 账号），不含空白 |
| 密码 | 明文存储（遵循项目"文件不加密"约定），不含空白 |
| 状态 | `E` = 启用，`D` = 停用（停用的账号认证一律失败） |
| 组 | 分组标记（默认 `users`），仅作记录与展示 |
| 备注 | 可含空格（前 4 个字段之后的全部内容并入备注） |

> - WebAdmin「用户管理」页可视化增删改；写文件走 `tmp → 原子替换` 并保留 `.bak` 备份。
> - **证书登录（EAP-TLS）不需要在这里建账号**：服务端以客户端证书 DN 作为身份放行（日志显示 `用户=CN=...（客户端证书: ...）`）。

### 7.5 `PKI/logs.log`（操作日志）

**只追加**，每条记录五段：**时间 / 时间戳 / 操作 / 命令 / 结果**，记录之间以**两个换行**分隔。所有操作（Admin 命令、WEB 请求、CRT/CRL/OCSP/时间戳请求、签名与验签、RADIUS/PPPoE 认证与调试）都会写入。

```
时间: 2026/10/13 06:00:33
时间戳: 1791842433272
操作: Radius 认证
命令: 来源=10.255.228.225:36965 用户=1.2.840.113549.1.9.1=#1611...,CN=localhost,... 方法=EAP(EAP-TLS)
结果: 认证通过
```

> WebAdmin「操作日志」页可按时间范围筛选浏览；RADIUS 的**实时**握手细节（含 `[iOS兼容]` 重传/重启日志、`[DBG]` 分片下发）在「Radius服务管理 → 服务器日志」的内存环形日志（最近 500 条）里查看。

### 7.6 `PKI/CTLOG/`（CT 日志）

| 文件 | 格式 |
|---|---|
| `modpkica_ct_list.json` | v3 风格密钥库：`[{描述, type(ECDSA/RSA/SM2), 私钥, 公钥, log_id, usable}...]`；由 WebAdmin「SCT服务管理 → CT日志密钥管理」维护 |
| `ctlogs.txt` | 每密钥一行：`SCT待签名摘要||时间戳||终端SKI||终端AKI||日志公钥ID`（只追加） |

---

## 八、证书类型与命名规则

| 类型 | 含义 | 密钥存储 | 对外 | 典型用途 |
|---|---|---|---|---|
| `R` | 根证书（自签） | `ROOT/序列号.crt` + `.key` | `WebPublic/CRT/序列号.crt` | 信任锚（客户端必须安装） |
| `C` | 中间 CA | `CA/序列号.crt` + `.key` | 同上 | 分级签发 |
| `E` | 终端证书 | `CERT/序列号.crt` + `KEY/序列号.key` | 同上 | **网关证书（serverAuth）/ EAP-TLS 客户端证书（clientAuth）/ 代码签名 / 文档签名 / TSA / OCSP 签名** |
| OCSP 专用 | OCSP 响应签名 | `OCSP/序列号_ocsp.crt` + `_ocsp.key` | 同上 | 由 `initOCSP` / 面板签发 |
| TSA 专用 | 时间戳签名 | `TIMSTAMP/类型_哈希.crt/.key` | 同上 | 由 `initTIMESTAMP` / 面板签发 |

> 所有证书签发后同时按 `序列号.crt` 同步到 `WebPublic/CRT/`，供 `/CRT/{序列号}.crt` 下载。
> **EKU 速查**：服务器身份验证 `1.3.6.1.5.5.7.3.1`；客户端身份验证 `1.3.6.1.5.5.7.3.2`；代码签名 `…3.3`；文档签名 `1.3.6.1.4.1.311.10.3.12` 或 `1.3.6.1.5.5.7.3.36`；时间戳 `…3.8`；OCSP 签名 `…3.9`。**网关证书要 serverAuth；EAP-TLS 客户端证书要 clientAuth（建议同时勾选两者）**。

---

## 九、VPN 网关接入（strongSwan）

MODPKICA 的 RADIUS 服务本身只处理认证（UDP 1812/1813）；手机 / Windows / macOS 的 **IKEv2 拨号由 Linux strongSwan 网关承接**，网关把 EAP 报文转发给本程序。完整部署步骤、逐字段配置解释、客户端拨号参数与故障排查见 **《[strongSwan接入指南](strongSwan接入指南.md)》**。

**最短路径（网关一键脚本）**：

```bash
# 1) Windows 主机侧：签发网关证书（WebAdmin → 签发证书，或命令行）
#    EKU 勾选"服务器身份验证"；SAN 同时填域名与服务器 IP（Windows 用 IP 拨号必须）；扩展控制 noAIA

# 2) 拷证书 + 脚本到 Linux 网关
scp PKI/CERT/{网关序列号}.crt root@网关IP:/tmp/gw.crt
scp PKI/KEY/{网关序列号}.key  root@网关IP:/tmp/gw.key
scp PKI/ROOT/{根序列号}.crt   root@网关IP:/tmp/root.crt
scp linux/install_strongswan.sh root@网关IP:/tmp/

# 3) 一键部署（参数：RADIUS 服务器 IP / 共享密钥 / 网关 ID）
ssh root@网关IP "bash /tmp/install_strongswan.sh 10.255.228.55 mytestkey vpn.local"
#   可选环境变量：POOL_ADDRS / VPN_DNS / GW_CRT / GW_KEY / ROOT_CRT / NO_NAT=1 / NO_PERSIST=1
#   脚本会做：装包 → 单元解析 → 证书校验(配对/SAN含本机IP/EKU/有效期/链接) → 写 eap-radius.conf
#             → 写 swanctl.conf(密码/证书 × 域名/IP 四条连接) → 内核转发 → NAT+FORWARD+MSS
#             → 启动 → swanctl --load-all → 连接清单校验 → RADIUS 连通性自检
```

**网关生成的两个配置文件**（脚本自动写入，也可手工维护）：

| 文件 | 作用 | 关键字段 |
|---|---|---|
| `/etc/strongswan.d/charon/eap-radius.conf` | RADIUS 转发插件 | `servers.primary.address/secret/auth_port/acct_port`（**必须与 `PKI/CONFIG.txt` 的 `RADIUSKEY` 一致**） |
| `/etc/swanctl/swanctl.conf` | IKEv2 连接与地址池 | 4 条连接（`ikev2-mschapv2` / `-ip`、`ikev2-eaptls` / `-ip`）、`pools.vpnpool.addrs/dns` |

> - 客户端证书登录（EAP-TLS）的**服务端证书**取 `PKI/CERT/`，可用 `CONFIG.txt` 的 `RADIUSCERT=序列号` 固定；客户端证书由 MODPKICA 签发（EKU ≥ clientAuth），打包 `.pfx` 导入手机。
> - 详细字段说明、`send_cert = always` / `eap_id = %any` / `cacerts` 等参数为什么必须这么写、iOS 与 Windows 的差异、以及 12 节故障排查表，都在指南里。

---

## 十、常见问题 FAQ

**Q1：编译/运行时中文乱码？**
A：必须带 `-Dfile.encoding=UTF-8` 运行；源码编译已用 `-encoding UTF-8`。脚本注释使用英文避免 cmd 代码页问题。

**Q2：`Address already in use: bind`？**
A：WEB 端口（默认 80）或管理端口（8080）被占用。`netstat -ano | findstr :80` 找到 PID 结束旧进程，或改 `CONFIG.txt` 的 `WEBPORT` / `SUPORT`。

**Q3：OCSP 报"未知序列号"？**
A：确认 CERTS.txt 有记录、`WebPublic/CRT/序列号.crt` 存在、`OCSP/颁发者序列号_ocsp.crt` 已生成（先运行 `initOCSP`）。

**Q4：Wosign 代码签名选 RFC3161 时间戳失败？**
A：RFC3161 时间戳用于 PDF 文档签名；微软代码签名请选 **Authenticode** 类型（`/timestamp` 或 `/timestamp/sha1`）。

**Q5：签发 ECC 证书报错？**
A：确认密钥位数按 ECC 曲线选择（256/384/521），且 BC 1.85 的 `BC185/` 完整放入项目根。

**Q6：SM2 已吊销证书 OCSP 验证报 `OCSP无法检查吊销状态 | 上报失败~`？**
A：v1.1 已修复（`CertStatus.revoked` 的 `[1] IMPLICIT RevokedInfo` 编码）。RSA / ECC 不受影响；升级后重启 MAIN 生效。

**Q7：如何离线开发？**
A：所有依赖只有 `BC185/` 全家桶 + `lib/`（pdfbox），无 Maven 仓库；改完源码直接 `build.cmd` / `./build.sh` 编译，`out/` 即产物。

**Q8：国密 PDF 签章（35275 / 38540 / 0031）报错？**
A：三者都**必须**使用 SM2 证书，且**必须**选择签章图片（png/jpg/bmp/gif）。GB/T 38540-2020 与 GM/T 0031-2025（`GM.sm2seal`）无标准时间戳扩展，即使填了时间戳地址也不嵌入；GB/T 35275-2017（`GM.sm2cms.detached`）为 CMS 结构可正常验签（SM3withSM2 含 ZA）。若用非 SM2 证书或未选图片，面板会给出明确中文错误。

**Q9：签名时时间戳地址填了外网 TSA 但失败？**
A：离线 / 无外网环境会请求失败，但签名**不中断**——时间戳失败自动降级（日志记录原因），文件照常签名成功。连接外部 TSA 需本机可访问其 80/443 端口；留空则使用本机 MAIN 时间戳服务。

**Q10：手机/Windows 证书登录（EAP-TLS）失败，网关与 RADIUS 日志怎么读？**
A：见《strongSwan接入指南》第 12 节。快速判据：RADIUS 环形日志里
- 正常成功：`EAP-TLS 认证通过 …（客户端证书: CN=…）` + `[DBG] EAP-TLS 已下发 MS-MPPE 密钥 32+32B`；
- 网关整包重传（同一 ClientHello 重复）：`[iOS兼容] EAP-TLS 检测到网关重传…（scope=…，快照…，片偏移…）`——这是**按事务重放**，r20 起不再打乱 TLS；若该行刷屏不停，说明客户端始终没接受服务端飞行，看网关侧 `journalctl -u strongswan -f`；
- 客户端中途重开握手：`[iOS兼容] EAP-TLS 客户端重启握手…→ 重建会话`（r20 起自动恢复）；
- `EAP-TLS 会话已失效` / `握手失败: …`：`eap-radius.conf` 的密钥或超时、或客户端证书不被信任。

**Q11：RADIUS 共享密钥改了以后哪些地方要同步？**
A：`PKI/CONFIG.txt` 的 `RADIUSKEY`（服务端）与网关 `/etc/strongswan.d/charon/eap-radius.conf` 的 `servers.primary.secret`（客户端）；改完 `systemctl restart strongswan` 并重启 MAIN/RADIUS 服务。

---

## 十一、更新记录

近期版本摘要（完整历史见 **[CHANGELOG.md](CHANGELOG.md)**）：

- **v1.28-r20（2026-10-13）** EAP-TLS 重传「事务化」：重放该笔响应（修"重传回末片"无限循环）、空拉取片重传不再跳片、服务端 Request Identifier 自增（RFC 3748 §4.1）、客户端重启握手自动重建会话。回归：126 项单元测试 + RADIUS/OCSP 冒烟 + EAP-TLS 证书登录 EAP-Success/64B MSK + iOS 重传用例 [1]-[8] 全过。
- **v1.28-r19（2026-10-13）** EAP-TLS 证书登录全线打通（Win11 / iOS / 安卓 / strongSwan）：修 TLS 1.2 ServerKeyExchange 签名算法错配（PSS 却声明 PKCS#1）、消除 TLS 1.3 降级哨兵、修客户端畸形 EAP-Message 切分。
- **v1.28-r18（2026-10-12）** 安全加固轮：签名/签发链路校验、EAP-TLS 客户端证书策略（全链有效期 + 吊销 + 账户状态）、RADIUS Message-Authenticator 强制、计费包完整性、会话表 TTL 回收、CERTS.txt 快照式读写与跨进程锁、CRL 原子写、私钥落盘权限。
- **v1.28-r17（2026-10-11）** iOS 原生 IKEv2 兼容：EAP-TLS 网关重传检测（RFC 3748 §5.1）——识别同 EAP-Id + 同数据指纹的重传并重发响应，修复 `unexpected_message(10)`。
- **v1.28-r16（2026-10-10）** EAP-TLS 证书登录全链路打通：MSK 手工导出 + MS-MPPE 32+32B 下发 + 网关接入文档与一键脚本。

---

## 十二、许可

本程序仅供学习 X.509 / ASN.1 / PKI 协议实现使用；作者不承担任何由此产生的问题。作者：**@魔帝本尊**（QQ：2829969554）。
