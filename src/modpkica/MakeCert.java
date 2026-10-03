package modpkica;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * MakeCert —— 签发下级证书（对应 Go 版 cmd/makecert）。
 *
 * <p>三种模式：
 * <ul>
 *   <li><b>普通签发</b>：{@code MakeCert "CN=xxx,O=yyy" 2048 sha256 RSA 1 3 0 1 "domain.com" "1.2.3.4" null &lt;颁发者ID&gt; &lt;算法&gt;}</li>
 *   <li><b>initOCSP</b>：{@code MakeCert initOCSP RSA &lt;颁发者ID&gt;} —— 生成 OCSP 签名证书（文件名 序列号_ocsp.crt/.key）</li>
 *   <li><b>initTIMSTAMP</b>：{@code MakeCert initTIMSTAMP SHA256 RSA} —— 生成 TSA 证书（文件名 类型_哈希.crt/.key）</li>
 * </ul>
 *
 * <p>参数（对齐 Go 版 os.Args）：
 * <pre>
 *   [1] DN 字符串（逗号分隔 key=value，% 替换为空格）或 initOCSP / initTIMSTAMP
 *   [2] 密钥位数（普通模式） / 哈希类型 SHA1|SHA256|SM3（initTIMSTAMP） / 算法（initOCSP）
 *   [3] 哈希（普通模式） / 颁发者ID（initOCSP） / 算法（initTIMSTAMP）
 *   [4] KeyUsage 类型（1~8，普通模式）
 *   [5] ExtKeyUsage 编号列表（逗号分隔，0~46）
 *   [6] 是否 CA（"1"=中间CA）
 *   [7] 有效期（年数 或 "开始T结束"）
 *   [8] 域名列表（逗号分隔，SAN）
 *   [9] IP 列表（逗号分隔，SAN）
 *   [11] 颁发者ID（CERTS.txt 中 R/C 类型证书序列号）
 *   [12] 使用者算法类型 RSA/ECC/SM2
 * </pre>
 *
 * <p>输出：普通证书写 PKI/CERT 或 PKI/CA + PKI/KEY + PKI/WebPublic/CRT；
 * initOCSP 写 PKI/OCSP/序列号_ocsp.crt|.key；initTIMSTAMP 写 PKI/TIMSTAMP/类型_哈希.crt|.key；
 * 并向 CERTS.txt 追加登记（类型 R/C/E，时间=当前-3天，对齐 Go 版）。
 */
public final class MakeCert {

    private static final DateTimeFormatter MOD_TIME =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    /** ExtKeyUsage 12~46 自定义 OID（对齐 Go 版 makecert switch） */
    private static final String[][] EXT_OIDS = {
            {"12", "1.3.6.1.4.1.311.2.1.22"},
            {"13", "1.3.6.1.4.1.311.61.1.1"},
            {"14", "1.3.6.1.4.1.311.10.3.5"},
            {"15", "1.3.6.1.4.1.311.10.3.6"},
            {"16", "1.3.6.1.4.1.311.10.3.7"},
            {"17", "1.3.6.1.4.1.311.10.3.8"},
            {"18", "1.3.6.1.4.1.311.64.1.1"},
            {"19", "1.3.6.1.4.1.311.47.1.1"},
            {"20", "1.3.6.1.4.1.311.10.3.19"},
            {"21", "1.3.6.1.5.2.3.5"},
            {"22", "1.3.6.1.4.1.311.10.3.13"},
            {"23", "1.3.6.1.4.1.311.21.5"},
            {"24", "1.3.6.1.4.1.311.10.3.10"},
            {"25", "1.3.6.1.4.1.311.10.3.11"},
            {"26", "1.3.6.1.4.1.311.10.3.12"},
            {"27", "1.3.6.1.4.1.311.10.3.2"},
            {"28", "1.3.6.1.4.1.311.10.3.4"},
            {"29", "1.3.6.1.4.1.311.21.6"},
            {"30", "1.3.6.1.4.1.311.21.19"},
            {"31", "1.3.6.1.5.5.8.2.2"},
            {"32", "1.3.6.1.4.1.311.10.3.4.1"},
            {"33", "1.3.6.1.4.1.311.10.3.9"},
            {"34", "1.3.6.1.4.1.311.10.5.1"},
            {"35", "1.3.6.1.4.1.311.20.1"},
            {"36", "1.3.6.1.4.1.311.10.6.1"},
            {"37", "1.3.6.1.4.1.311.10.6.2"},
            {"38", "1.3.6.1.4.1.311.20.2.1"},
            {"39", "1.3.6.1.4.1.311.20.2.2"},
            {"40", "1.3.6.1.4.1.311.21.30"},
            {"41", "1.3.6.1.4.1.311.21.31"},
            {"42", "1.3.6.1.4.1.311.21.32"},
            {"43", "1.2.840.113635.100.4.1"},
            {"44", "1.2.840.113635.100.4.1.1"},
            {"45", "1.2.840.113635.100.4.1.4"},
            {"46", "1.2.840.113635.100.4.2"}
    };

    /** 服务模式安静开关：由 WebAdmin / MAIN 置位后，生成成功信息不再打印到控制台
     *  （避免服务控制台刷屏/卡死），改写入 PKI/logs.log 日志文件；CLI 直接运行不受影响。 */
    private static volatile boolean quiet = false;

    /** 设置安静模式（服务进程内调用，执行完应恢复 false）。 */
    public static void setQuiet(boolean q) {
        quiet = q;
    }

    private MakeCert() {
    }

    /** 生成结果输出：控制台（非安静模式）+ 操作日志（始终写入，保证服务模式有据可查）。 */
    private void out(String msg) {
        if (!quiet) {
            System.out.println(msg);
        }
        try {
            MLog.append(baseDir, "MakeCert输出", "签发证书", msg);
        } catch (Exception ignore) {
            // 日志写入失败不影响签发主流程
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("用法: MakeCert \"DN(逗号分隔key=value)\" 密钥位数 哈希 算法 [KeyUsage] [ExtKeyUsage] [IsCA] [有效期] [域名] [IP] [null] 颁发者ID 算法");
            System.out.println("      MakeCert initOCSP RSA|ECC|SM2 颁发者ID");
            System.out.println("      MakeCert initTIMSTAMP SHA1|SHA256|SM3 RSA|ECC|SM2");
            return;
        }
        run(AppPaths.baseDir(), args);
    }

    /** 供 ADMIN 内部调用：指定工作目录签发。 */
    public static void run(String baseDir, String[] a) throws Exception {
        MakeCert m = new MakeCert();
        m.baseDir = baseDir;
        m.run(a);
    }

    private String baseDir;
    private Config cfg;

    private void run(String[] a) throws Exception {
        cfg = new Config(baseDir);

        String mode = a[0];
        boolean isOcsp = "initOCSP".equals(mode);
        boolean isTsa = "initTIMSTAMP".equals(mode);

        // ---- 颁发者加载（序列号 → ROOT/CA 目录；多根模型无 root 别名） ----
        // 普通模式参数布局（对齐 Go 版 makecert MODML[1..12]）：
        //   a[0]=DN a[1]=bit a[2]=hash a[3]=keyusage a[4]=exoid a[5]=isca
        //   a[6]=txtime a[7]=域名 a[8]=IP a[9]=Kernel a[10]=颁发者ID a[11]=算法
        // initOCSP：a={"initOCSP", 算法, 颁发者序列号}；initTIMSTAMP：a={"initTIMSTAMP", 哈希, 算法, 颁发者序列号}
        String issuerId;
        if (isOcsp) {
            issuerId = a.length >= 3 ? a[2] : null;
        } else if (isTsa) {
            issuerId = a.length >= 4 ? a[3] : null;
        } else {
            issuerId = a.length >= 11 ? a[10] : null;
        }
        if (issuerId == null || issuerId.isEmpty()) {
            throw new IllegalArgumentException(
                    "缺少颁发者ID：必须传入 CERTS.txt 中类型 R（根）/ C（中间CA）的证书序列号");
        }
        String issuerPath = resolveIssuer(issuerId);
        X509Certificate issuerCert = PemIO.readCert(issuerPath + ".crt");
        String rootAlgo = PemIO.detectKeyType(issuerPath + ".key");
        // RSA-PSS：RSA 私钥文件本身无法区分 PSS 与 PKCS#1，必须按 CERTS.txt 中
        // 颁发者登记算法列判断，否则会退化为 PKCS#1 v1.5 签名。
        {
            CertsDB db0 = new CertsDB();
            db0.load(baseDir);
            CertsDB.CertEntry ie0 = db0.findBySerial(issuerId);
            if (ie0 != null && "RSA-PSS".equalsIgnoreCase(ie0.algo)) {
                rootAlgo = "RSA-PSS";
            }
        }
        java.security.PrivateKey issuerKey = CertUtil.readJcaPrivateKey(issuerPath + ".key");
        // PKI-009: revoke/expired/non-CA issuer must not be able to sign new certificates
        checkIssuerUsable(issuerCert, issuerId);

        // ---- 使用者算法与密钥 ----
        String certAlgo;
        int certBit;
        String tsaHash = null;
        if (isOcsp) {
            certAlgo = a[1].toUpperCase(Locale.ROOT);
            certBit = defaultBit(certAlgo);
        } else if (isTsa) {
            tsaHash = a[1].toUpperCase(Locale.ROOT);
            certAlgo = a[2].toUpperCase(Locale.ROOT);
            certBit = defaultBit(certAlgo);
        } else {
            // 普通模式参数布局（对齐 Go 版 makecert MODML[1..12]）：
            //   a[0]=DN a[1]=bit a[2]=hash a[3]=keyusage a[4]=exoid a[5]=isca
            //   a[6]=txtime a[7]=域名 a[8]=IP a[9]=Kernel a[10]=颁发者ID a[11]=算法
            certAlgo = a.length >= 12 ? a[11].toUpperCase(Locale.ROOT) : "RSA";
            certBit = parseBit(a[1], certAlgo);
        }
        // PQC（ML-DSA-44/65/87）：密钥位数参数为规格字符串（如 ML-DSA-65）
        KeyPair certKp = "PQC".equals(certAlgo)
                ? CertUtil.generatePqcKeyPair(a[1])
                : generateKeyPair(certAlgo, certBit);

        // ---- 签名算法（对齐 Go 版 roothash 逻辑） ----
        String hash = resolveSignHash(a, rootAlgo, isOcsp, isTsa, tsaHash);

        // ---- 使用者信息 ----
        X500Name subject;
        String certCn;
        if (isOcsp || isTsa) {
            String ou;
            String cnSuffix;
            if (isOcsp) {
                ou = "Only OCSP Signing";
                cnSuffix = " By OCSP";
            } else {
                ou = "Only TSA " + tsaHash + " Signing";
                cnSuffix = " By Timstamp " + tsaHash;
            }
            certCn = issuerCert.getSubjectX500Principal().getName()
                    .replaceFirst("^CN=[^,]+,?", ""); // 去除原 CN，保留其余
            // 简化：直接取原证书 CN
            certCn = extractCn(issuerCert) + cnSuffix;
            X500NameBuilder b = new X500NameBuilder();
            copySubject(b, issuerCert, certCn, ou);
            subject = b.build();
        } else {
            subject = buildSubject(a[0]);
            certCn = subject.toString();
        }

        // ---- 有效期 ----
        Date notBefore;
        Date notAfter;
        if (isOcsp || isTsa) {
            notBefore = new Date();
            notAfter = new Date(notBefore.getTime() + 365L * 24 * 3600 * 1000);
        } else {
            Date[] times = parseValidity(a.length >= 7 ? a[6] : null);
            notBefore = times[0];
            notAfter = times[1];
        }

        // ---- 序列号 ----
        boolean isCa = !isOcsp && !isTsa && a.length >= 6 && "1".equals(a[5]);
        BigInteger serial = buildSerial(isCa);

        // ---- 中间CA 路径长度 / 终端证书策略 OID（Web 面板扩展参数 a[12]/a[13]） ----
        // a[12]=pathlen：null 或 0-9（仅中间CA 生效）；a[13]=policy：逗号分隔的策略 OID（仅终端证书生效）
        Integer pathLen = null;
        if (!isOcsp && !isTsa && a.length >= 13 && a[12] != null) {
            String pl = a[12].trim();
            if (!pl.isEmpty() && !"null".equalsIgnoreCase(pl)) {
                try {
                    pathLen = Integer.valueOf(pl);
                } catch (NumberFormatException ignore) {
                    pathLen = null;
                }
            }
        }
        String policyArg = (!isOcsp && !isTsa && a.length >= 14 && a[13] != null) ? a[13].trim() : null;

        // ---- KeyUsage ----
        // 注意：Go 版 x509.KeyUsage 位定义与 BC 不同，统一用 goKeyUsageToBc 转换
        int keyUsage;
        if (isOcsp || isTsa) {
            keyUsage = goKeyUsageToBc(1);
        } else if (isCa) {
            keyUsage = goKeyUsageToBc(1 | 2 | 32 | 64);
        } else {
            keyUsage = goKeyUsageToBc(parseKeyUsage(a.length >= 4 ? a[3] : null));
            // PKI-010: End Entity (CA=false) MUST NOT assert keyCertSign
            if ((keyUsage & KeyUsage.keyCertSign) != 0) {
                throw new IllegalArgumentException(
                        "terminal certificate (End Entity, CA=false) cannot carry keyCertSign KeyUsage");
            }
        }
        // P2-09：CA 模式强制 keyCertSign，拒绝 BasicConstraints=CA 但 KU 缺 keyCertSign 的矛盾证书
        if (isCa && (keyUsage & KeyUsage.keyCertSign) == 0) {
            throw new IllegalArgumentException(
                    "CA certificate must carry keyCertSign KeyUsage");
        }

        // ---- ExtKeyUsage ----
        List<KeyPurposeId> eku = new ArrayList<>();
        List<ASN1ObjectIdentifier> unknownEku = new ArrayList<>();
        boolean needCt = false;
        if (isOcsp) {
            eku.add(KeyPurposeId.id_kp_OCSPSigning);
        } else if (isTsa) {
            eku.add(KeyPurposeId.id_kp_timeStamping);
        } else {
            String ex = a.length >= 5 ? a[4] : null;
            if (ex != null && !"null".equals(ex) && !ex.isEmpty()) {
                String[] nums = ex.contains(",") ? ex.split(",") : new String[]{ex};
                for (String n : nums) {
                    String t = n.trim();
                    if (t.isEmpty()) {
                        continue;
                    }
                    // 1) 数字编号：0=任意 1=服务器认证 ...（Go 版 MODSUEKU 编号表）
                    try {
                        int num = Integer.parseInt(t);
                        if (num < 12) {
                            KeyPurposeId kp = builtinEku(num);
                            if (kp != null) {
                                eku.add(kp);
                            }
                            if (num == 1 || num == 2) {
                                needCt = true; // 域名 SSL 用途触发 CT 扩展
                            }
                        } else {
                            String oid = extOid(num);
                            if (oid != null) {
                                unknownEku.add(new ASN1ObjectIdentifier(oid));
                            }
                        }
                        continue;
                    } catch (NumberFormatException ignored) {
                        // 不是编号，走 OID 解析
                    }
                    // 2) OID 格式：数字点分（如 1.3.6.1.5.5.7.3.1），直接作为增强型密钥用法；
                    //    含服务器身份验证(1.3.6.1.5.5.7.3.1)/客户端身份验证(1.3.6.1.5.5.7.3.2)必须携带 SCT 列表
                    if (isValidOid(t)) {
                        unknownEku.add(new ASN1ObjectIdentifier(t));
                        if ("1.3.6.1.5.5.7.3.1".equals(t) || "1.3.6.1.5.5.7.3.2".equals(t)) {
                            needCt = true;
                        }
                    }
                }
            }
        }

        // ---- 证书构建 ----
        // 证书签名算法由"颁发者私钥"决定（对齐 Go 版：用 root 私钥签）
        ContentSigner signer = CertUtil.createContentSigner(issuerKey, rootAlgo,
                "SM2".equals(rootAlgo) ? "sm3" : hash);

        // ---- 证书构建（RFC 6962 流程）----
        // 需 CT 透明度时：先构建含 poison 扩展的 SCT 预证书 → 提交自身 CT 日志
        // /ct/add 取回 SCT 列表 → 重建（去 poison、加 SCT 扩展）签发最终证书。
        // 其它场景直接一次构建签发。
        byte[] issuerSki = CertUtil.getSubjectKeyIdentifier(issuerCert.getPublicKey());
        byte[] userSki = CertUtil.getSubjectKeyIdentifier(certKp.getPublic());
        String serialHex = serial.toString(16);
        String ocspUrl = cfg.getOcspUrl();
        String crtUrl = cfg.getCrtUrl().replace("{CID}", issuerCert.getSerialNumber().toString(16));
        String crlUrl = cfg.getCrlUrl().replace("{CID}", issuerCert.getSerialNumber().toString(16));

        // CPS 证书策略扩展（参考 smplus 组合方式：CertificatePolicies 标准类，一次生成不重复）
        // 合成：带 CPS URI + UserNotice 限定符的策略 + 其余纯 OID 策略
        // TSA 证书额外增加策略 OID 2.23.140.1.4.2（TSA 证书标记）
        String[] cpsOids;
        if (isCa) {
            cpsOids = new String[]{"1.3.6.1.4.1.4146.1.95", "2.5.29.32.0", "1.3.6.1.4.1.311.10.12.1"};
        } else if (isTsa) {
            cpsOids = new String[]{"1.3.6.1.4.1.4146.1.95", "2.23.140.1.1", "2.23.140.1.3", "2.23.140.1.4.2"};
        } else {
            // 终端证书：基础策略 4146.1.95（带 CPS+UserNotice）+ 面板勾选的策略 OID（勾选才写入）
            java.util.List<String> pol = new java.util.ArrayList<>();
            pol.add("1.3.6.1.4.1.4146.1.95");
            if (policyArg != null && !policyArg.isEmpty() && !"null".equalsIgnoreCase(policyArg)) {
                for (String o : policyArg.split(",")) {
                    String t = o.trim();
                    if (!t.isEmpty() && !pol.contains(t)) {
                        pol.add(t);
                    }
                }
            }
            cpsOids = pol.toArray(new String[0]);
        }
        // 用户通告默认文本：对齐 Go 版——CONFIG 未显式配置 CPS_Nonice 时用默认通告，
        // 显式写 null 才留空（Go 版 makecert MODSUCPS_Nonice 逻辑）
        String cpsText = cfg.getCpsNonice();
        boolean cpsNoniceExplicit = cfg.getRaw().containsKey("CPS_Nonice");
        if (cpsText == null || cpsText.isEmpty()) {
            cpsText = "这是MODPKICA的证书颁发策略用户通告内容。/This is MODPKICA CPS Nonice Text.";
        } else if (cpsNoniceExplicit && "null".equalsIgnoreCase(cpsText)) {
            cpsText = "";
        }
        // CONFIG 中字面 \n 转真实换行（配置页以单行 \n 存储，证书内需真实换行）
        cpsText = cpsText.replace("\\n", "\n");
        CertificatePolicies certPolicies = buildCpsPolicies(cpsOids, cfg.getCps(), cpsText);

        X500Name issuerName = X500Name.getInstance(
                issuerCert.getSubjectX500Principal().getEncoded());
        String dnsArg = a.length >= 8 ? a[7] : null;
        String ipsArg = a.length >= 9 ? a[8] : null;

        X509CertificateHolder holder;
        if (needCt && !isCa) {
            // 1) SCT 预证书：全部扩展 + poison（critical，RFC 6962 §3.1）
            JcaX509v3CertificateBuilder cbPre = buildCertBuilder(
                    issuerName, serial, notBefore, notAfter, subject, certKp.getPublic(),
                    isCa, pathLen, keyUsage, issuerSki, userSki, eku, unknownEku, isTsa, isOcsp,
                    ocspUrl, crtUrl, crlUrl, certPolicies, dnsArg, ipsArg, true);
            X509CertificateHolder precert = cbPre.build(signer);
            // 2) 按 CONFIG.txt CTLOGapi 指定接口提交自身 CT 日志服务（预证书 + 颁发者），取回 SCT 列表
            byte[] sctList = CtLog.submitPrecert(baseDir, precert, issuerCert, issuerKey, rootAlgo, hash,
                    cfg.getWebPort());
            // 3) 最终证书：重建（无 poison）+ SCT 列表扩展（1.3.6.1.4.1.11129.2.4.2）
            JcaX509v3CertificateBuilder cbFin = buildCertBuilder(
                    issuerName, serial, notBefore, notAfter, subject, certKp.getPublic(),
                    isCa, pathLen, keyUsage, issuerSki, userSki, eku, unknownEku, isTsa, isOcsp,
                    ocspUrl, crtUrl, crlUrl, certPolicies, dnsArg, ipsArg, false);
            cbFin.addExtension(new ASN1ObjectIdentifier(CtLog.OID_SCT), false,
                    new DEROctetString(sctList));
            holder = cbFin.build(signer);
        } else {
            holder = buildCertBuilder(
                    issuerName, serial, notBefore, notAfter, subject, certKp.getPublic(),
                    isCa, pathLen, keyUsage, issuerSki, userSki, eku, unknownEku, isTsa, isOcsp,
                    ocspUrl, crtUrl, crlUrl, certPolicies, dnsArg, ipsArg, false)
                    .build(signer);
        }
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(holder);

        // ---- 输出文件 ----
        writeOutputs(cert, certKp, certAlgo, serialHex, isCa, isOcsp, isTsa, issuerId, tsaHash);
    }

    // ===================== 以下为辅助方法 =====================

    private String resolveIssuer(String id) {
        // 多根模型：只按序列号从 CA / ROOT 目录加载，无 root 别名
        if (java.nio.file.Files.exists(java.nio.file.Paths.get(baseDir + "/PKI/CA/" + id + ".crt"))) {
            return baseDir + "/PKI/CA/" + id;
        }
        if (java.nio.file.Files.exists(java.nio.file.Paths.get(baseDir + "/PKI/ROOT/" + id + ".crt"))) {
            return baseDir + "/PKI/ROOT/" + id;
        }
        throw new IllegalArgumentException("此ID既不是根证书也不是中间CA证书: " + id);
    }

    /** 签发前校验颁发者可用性（PKI-009/PKI-010）：有效期、CA 属性、keyCertSign、吊销状态。
     *  "文件存在"不能等于"允许作为 CA 继续签发"。 */
    private void checkIssuerUsable(X509Certificate issuerCert, String issuerId) throws Exception {
        java.util.Date now = new java.util.Date();
        if (now.before(issuerCert.getNotBefore())) {
            throw new IllegalArgumentException("issuer certificate not yet valid: " + issuerCert.getNotBefore());
        }
        if (now.after(issuerCert.getNotAfter())) {
            throw new IllegalArgumentException("issuer certificate expired: " + issuerCert.getNotAfter());
        }
        if (issuerCert.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("issuer certificate is not a CA (BasicConstraints CA=false), cannot sign");
        }
        boolean[] ku = issuerCert.getKeyUsage();
        if (ku != null && (ku.length <= 5 || !ku[5])) {
            throw new IllegalArgumentException("issuer certificate KeyUsage lacks keyCertSign, cannot sign certificates");
        }
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry = db.findBySerial(issuerId);
        if (entry == null) {
            throw new IllegalArgumentException("issuer not registered in CERTS.txt: " + issuerId
                    + "（仅允许台账中已登记的 R/C 证书作为颁发者）");
        }
        if (entry.type != 'R' && entry.type != 'C') {
            throw new IllegalArgumentException("issuer type in CERTS.txt must be R or C, got: " + entry.type);
        }
        if (entry.status == 'R') {
            throw new IllegalArgumentException("issuer certificate is revoked (status=R), signing forbidden");
        }
        // 文件证书序列号必须与台账一致（防止文件与台账编号错位）
        String fileSerial = issuerCert.getSerialNumber().toString(16);
        if (!fileSerial.equalsIgnoreCase(issuerId)) {
            throw new IllegalArgumentException("issuer file serial mismatch: file=" + fileSerial
                    + " ledger=" + issuerId);
        }
    }

    private int defaultBit(String algo) {
        if ("RSA".equals(algo) || "RSA-PSS".equals(algo)) {
            return 2048;
        }
        if ("DSA".equals(algo)) {
            return 2048;
        }
        return 256;
    }

    private int parseBit(String arg, String algo) {
        int bit;
        try {
            bit = Integer.parseInt(arg.trim());
        } catch (NumberFormatException e) {
            bit = 0;
        }
        if ("RSA".equals(algo) || "RSA-PSS".equals(algo)) {
            if (bit < 1024) {
                bit = 2048;
            }
            return bit;
        }
        if ("ECC".equals(algo)) {
            if (bit <= 0) {
                return 256;
            }
            if (bit <= 256) {
                return 256;
            }
            if (bit <= 384) {
                return 384;
            }
            return 521;
        }
        if ("DSA".equals(algo)) {
            // FIPS 186-4：L 取 1024/2048/3072 三档
            if (bit <= 0) {
                return 2048;
            }
            if (bit >= 3072) {
                return 3072;
            }
            if (bit >= 2048) {
                return 2048;
            }
            return 1024;
        }
        if ("EDDSA".equalsIgnoreCase(algo)) {
            return 256; // Ed25519 固定 256，忽略输入
        }
        return 256;
    }

    private KeyPair generateKeyPair(String algo, int bit) throws Exception {
        algo = algo.toUpperCase(Locale.ROOT); // 统一归一化，避免 EdDSA/EDDSA 大小写不一致
        switch (algo) {
            case "RSA":
            case "RSA-PSS":
                return CertUtil.generateRsaKeyPair(bit);
            case "ECC":
                return CertUtil.generateEccKeyPair(bit);
            case "SM2":
                return CertUtil.generateSm2KeyPair();
            case "DSA":
                return CertUtil.generateDsaKeyPair(bit);
            case "EDDSA":
                return CertUtil.generateEd25519KeyPair();
            case "PQC":
                return CertUtil.generatePqcKeyPair(String.valueOf(bit));
            default:
                throw new IllegalArgumentException("不支持的算法: " + algo);
        }
    }

    /** 决定证书签名算法哈希（对齐 Go 版 roothash 逻辑）。 */
    private String resolveSignHash(String[] a, String rootAlgo, boolean isOcsp, boolean isTsa,
                                   String tsaHash) {
        if (isOcsp || isTsa) {
            return "sha256"; // OCSP/TSA 证书签名统一 SHA256（微软拒绝 sha1 签名的证书）
        }
        String h = a.length >= 3 ? a[2].toLowerCase(Locale.ROOT) : "sha256";
        switch (h) {
            case "sha1":
                return "sha1";
            case "sha384":
                return "sha384";
            case "sha512":
                return "sha512";
            case "sha3-224":
                return "sha3-224";
            case "sha3-256":
                return "sha3-256";
            case "sha3-384":
                return "sha3-384";
            case "sha3-512":
                return "sha3-512";
            case "sm3":
            case "sm2":
                return "SM2".equals(rootAlgo) ? "sm3" : "sha256";
            default:
                return "sha256";
        }
    }

    private X500Name buildSubject(String dn) {
        X500NameBuilder builder = new X500NameBuilder();
        java.util.Map<String, String> fields = new java.util.LinkedHashMap<>();
        for (String part : dn.split(",")) {
            int idx = part.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = part.substring(0, idx).trim();
            String value = part.substring(idx + 1).trim().replace("%", " ");
            if (!value.isEmpty()) {
                fields.put(key, value);
            }
        }
        // 统一标准排序：按 X.500/RFC 规范顺序（C,ST,L,STREET,PostalCode,O,OU,SERIALNUMBER,CN），
        // EV 注册字段（jurisdiction* 注册市/省/国、organizationIdentifier、emailAddress）随后，
        // 自定义 OID 字段排最后并保持输入顺序。
        java.util.List<java.util.Map.Entry<String, String>> sorted =
                new java.util.ArrayList<>(fields.entrySet());
        sorted.sort(java.util.Comparator.comparingInt(e -> dnOrder(e.getKey())));
        for (java.util.Map.Entry<String, String> e : sorted) {
            addDnField(builder, e.getKey(), e.getValue());
        }
        return builder.build();
    }

    /** 统一 DN 属性排序权重（X.500/RFC 规范顺序，从根到叶）：C→ST→L→STREET→PostalCode→O→OU→SERIALNUMBER→CN，
     *  EV 注册字段（jurisdiction* 注册市/省/国、organizationIdentifier、emailAddress）随后，自定义 OID 最后。 */
    private static int dnOrder(String key) {
        switch (key) {
            case "C": case "2.5.4.6": return 10;                       // 国家
            case "S": case "ST": case "2.5.4.8": return 20;            // 省/州
            case "L": case "2.5.4.7": return 30;                       // 城市
            case "STREET": case "2.5.4.9": return 40;                  // 街道
            case "PostalCode": case "2.5.4.17": return 50;             // 邮编
            case "O": case "2.5.4.10": return 60;                      // 组织
            case "OU": case "2.5.4.11": return 70;                     // 组织单位
            case "SERIALNUMBER": case "2.5.4.5": return 80;            // 注册号
            case "CN": case "2.5.4.3": return 90;                      // 通用名称
            case "1.3.6.1.4.1.311.60.2.1.1": return 100;               // jurisdictionLocality 注册市
            case "1.3.6.1.4.1.311.60.2.1.2": return 110;               // jurisdictionStateOrProvince 注册省
            case "1.3.6.1.4.1.311.60.2.1.3": return 120;               // jurisdictionCountry 注册国家
            case "2.5.4.97": return 130;                               // organizationIdentifier 组织标识符
            case "1.2.840.113549.1.9.1": return 140;                   // emailAddress
            default: return 1000;                                      // 自定义 OID：保持输入顺序
        }
    }

    /** 按 key（短名或 OID）添加 RDN，非标准 key 直接按 OID 解析。 */
    private static void addDnField(X500NameBuilder builder, String key, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        switch (key) {
            case "C": addIfPresent(builder, BCStyle.C, value); return;
            case "O": addIfPresent(builder, BCStyle.O, value); return;
            case "OU": addIfPresent(builder, BCStyle.OU, value); return;
            case "L": addIfPresent(builder, BCStyle.L, value); return;
            case "S": case "ST": addIfPresent(builder, BCStyle.ST, value); return;
            case "STREET": addIfPresent(builder, BCStyle.STREET, value); return;
            case "PostalCode": addIfPresent(builder, BCStyle.POSTAL_CODE, value); return;
            case "SERIALNUMBER": addIfPresent(builder, BCStyle.SERIALNUMBER, value); return;
            case "CN": addIfPresent(builder, BCStyle.CN, value); return;
            default:
                try {
                    addIfPresent(builder, new ASN1ObjectIdentifier(key), value);
                } catch (Exception ignored) {
                    // 既不是标准字段也不是合法 OID：忽略该 RDN
                }
        }
    }

    /** 标准 DN 短名（Go 版 pkix.Name 支持的固定字段）。 */
    private static boolean isStandardDnKey(String key) {
        switch (key) {
            case "C": case "O": case "OU": case "L": case "S":
            case "STREET": case "PostalCode": case "SERIALNUMBER": case "CN":
                return true;
            default:
                return false;
        }
    }

    private void copySubject(X500NameBuilder b, X509Certificate issuerCert, String cn, String ou) {
        javax.security.auth.x500.X500Principal p = issuerCert.getSubjectX500Principal();
        String name = p.getName(javax.security.auth.x500.X500Principal.RFC2253);
        for (String rdn : name.split(",")) {
            int idx = rdn.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = rdn.substring(0, idx).trim();
            String value = rdn.substring(idx + 1).trim();
            if ("CN".equals(key)) {
                continue; // 使用新 CN
            }
            if ("OU".equals(key)) {
                continue; // 使用新 OU
            }
            addIfPresent(b, oidOf(key), value);
        }
        addIfPresent(b, BCStyle.OU, ou);
        addIfPresent(b, BCStyle.CN, cn);
    }

    private static ASN1ObjectIdentifier oidOf(String key) {
        switch (key) {
            case "C": return BCStyle.C;
            case "O": return BCStyle.O;
            case "OU": return BCStyle.OU;
            case "L": return BCStyle.L;
            case "ST": return BCStyle.ST;
            case "STREET": return BCStyle.STREET;
            case "POSTALCODE": return BCStyle.POSTAL_CODE;
            case "SERIALNUMBER": return BCStyle.SERIALNUMBER;
            case "CN": return BCStyle.CN;
            default:
                try {
                    return new ASN1ObjectIdentifier(key);
                } catch (Exception e) {
                    return BCStyle.CN;
                }
        }
    }

    private static void addIfPresent(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isEmpty()) {
            builder.addRDN(oid, value);
        }
    }

    private static String extractCn(X509Certificate cert) {
        String name = cert.getSubjectX500Principal().getName(
                javax.security.auth.x500.X500Principal.RFC2253);
        for (String rdn : name.split(",")) {
            if (rdn.startsWith("CN=")) {
                return rdn.substring(3);
            }
        }
        return "CN";
    }

    private Date[] parseValidity(String txt) throws Exception {
        if (txt == null || txt.isEmpty() || "null".equals(txt)) {
            return new Date[]{
                    new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss").parse("2011/12/08-21:18:57"),
                    new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss").parse("2051/01/02-15:04:05")};
        }
        if (txt.length() < 5) {
            int years = 1;
            try {
                years = Integer.parseInt(txt);
            } catch (NumberFormatException ignored) {
            }
            long now = System.currentTimeMillis();
            return new Date[]{new Date(now),
                    new Date(now + 365L * 24 * 3600 * 1000 * years)};
        }
        String[] parts = txt.split("T");
        SimpleDateFormat f = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss");
        return new Date[]{f.parse(parts[0]), f.parse(parts[1])};
    }

    private BigInteger buildSerial(boolean isCa) {
        // 128 位密码学安全随机正整数（避免同秒 / 并发签发碰撞）
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        java.util.Set<String> used = existingSerials();
        BigInteger serial;
        do {
            serial = new BigInteger(128, rnd);
        } while (serial.signum() <= 0 || used.contains(serial.toString(16)));
        return serial;
    }

    /** 读取 CERTS.txt 中已登记的序列号集合（十六进制小写），避免新序列号碰撞。 */
    private java.util.Set<String> existingSerials() {
        java.util.Set<String> used = new java.util.HashSet<>();
        try {
            java.nio.file.Path p = java.nio.file.Paths.get(baseDir + "/PKI/CERTS.txt");
            if (java.nio.file.Files.exists(p)) {
                for (String raw : java.nio.file.Files.readAllLines(p,
                        java.nio.charset.StandardCharsets.UTF_8)) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 1) {
                        used.add(parts[0].toLowerCase());
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return used;
    }

    /**
     * Go 版 x509.KeyUsage 位值 → BC KeyUsage 位值。
     *
     * <p>Go：DigitalSignature=1 ContentCommitment=2 KeyEncipherment=4
     * DataEncipherment=8 KeyAgreement=16 CertSign=32 CRLSign=64 EncipherOnly=128。
     * BC：digitalSignature=128 nonRepudiation=64 keyEncipherment=32
     * dataEncipherment=16 keyAgreement=8 keyCertSign=4 cRLSign=2 encipherOnly=1。
     */
    private static int goKeyUsageToBc(int go) {
        int bc = 0;
        if ((go & 1) != 0) bc |= KeyUsage.digitalSignature;
        if ((go & 2) != 0) bc |= KeyUsage.nonRepudiation;
        if ((go & 4) != 0) bc |= KeyUsage.keyEncipherment;
        if ((go & 8) != 0) bc |= KeyUsage.dataEncipherment;
        if ((go & 16) != 0) bc |= KeyUsage.keyAgreement;
        if ((go & 32) != 0) bc |= KeyUsage.keyCertSign;
        if ((go & 64) != 0) bc |= KeyUsage.cRLSign;
        if ((go & 128) != 0) bc |= KeyUsage.encipherOnly;
        if ((go & 256) != 0) bc |= KeyUsage.decipherOnly;
        return bc;
    }

    private int parseKeyUsage(String mode) {
        if (mode == null) {
            // 命令行完全缺省：保持默认通用组合（兼容历史行为）
            return 1 | 2 | 4 | 8 | 16;
        }
        if (mode.isEmpty() || "null".equalsIgnoreCase(mode)) {
            // 显式空值 = 证书不携带 KeyUsage 扩展
            return 0;
        }
        switch (mode) {
            case "1": return 1 | 2 | 4 | 8 | 16;
            case "2": return 1 | 2 | 32 | 64;
            case "3": return 128;
            case "4": return 256;
            case "5": return 1 | 2;
            case "6": return 8;
            case "7": return 4;
            case "8": return 16;
            default:
                // 自定义组合：支持 "C5" 前缀形式（WebAdmin 悬浮窗组合）与纯数字位值
                // （如 11=数字签名1+密钥加密4+数据加密8），直接按 Go 位值解析
                String v = mode;
                if (v.startsWith("C") || v.startsWith("c")) {
                    v = v.substring(1);
                }
                try {
                    return Integer.parseInt(v.trim());
                } catch (NumberFormatException e) {
                    return 1 | 2 | 4 | 8 | 16;
                }
        }
    }

    private static KeyPurposeId builtinEku(int num) {
        switch (num) {
            case 0: return KeyPurposeId.anyExtendedKeyUsage;
            case 1: return KeyPurposeId.id_kp_serverAuth;
            case 2: return KeyPurposeId.id_kp_clientAuth;
            case 3: return KeyPurposeId.id_kp_codeSigning;
            case 4: return KeyPurposeId.id_kp_emailProtection;
            case 5: return KeyPurposeId.id_kp_ipsecEndSystem;
            case 6: return KeyPurposeId.id_kp_ipsecTunnel;
            case 7: return KeyPurposeId.id_kp_ipsecUser;
            case 8: return KeyPurposeId.id_kp_timeStamping;
            case 9: return KeyPurposeId.id_kp_OCSPSigning;
            case 10: return KeyPurposeId.id_kp_msSGC;
            case 11: return KeyPurposeId.id_kp_nsSGC;
            default: return null;
        }
    }

    private static String extOid(int num) {
        for (String[] row : EXT_OIDS) {
            if (row[0].equals(String.valueOf(num))) {
                return row[1];
            }
        }
        return null;
    }

    /** OID 合法格式校验：数字.数字.数字...（至少两段） */
    private static boolean isValidOid(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        String[] parts = s.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || !p.chars().allMatch(Character::isDigit)) {
                return false;
            }
        }
        return true;
    }

    private static DERSequence buildEkuSequence(List<KeyPurposeId> eku,
                                                List<ASN1ObjectIdentifier> unknown) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (KeyPurposeId kp : eku) {
            v.add(kp);
        }
        for (ASN1ObjectIdentifier oid : unknown) {
            v.add(oid);
        }
        return new DERSequence(v);
    }

    private void addAuthorityInfoAccess(JcaX509v3CertificateBuilder cb,
                                        String ocspUrl, String caIssuerUrl) throws Exception {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (ocspUrl != null && !ocspUrl.isEmpty()) {
            vec.add(new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        if (caIssuerUrl != null && !caIssuerUrl.isEmpty()) {
            vec.add(new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, caIssuerUrl)));
        }
        if (vec.size() > 0) {
            cb.addExtension(Extension.authorityInfoAccess, false,
                    AuthorityInformationAccess.getInstance(new DERSequence(vec)));
        }
    }

    private void addCrlDistributionPoints(JcaX509v3CertificateBuilder cb, String crlUrl)
            throws Exception {
        if (crlUrl == null || crlUrl.isEmpty()) {
            return;
        }
        GeneralName gn1 = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        GeneralName gn2 = new GeneralName(GeneralName.uniformResourceIdentifier,
                crlUrl.replace(".crl", ".der.crl"));
        DistributionPoint dp1 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn1)), null, null);
        DistributionPoint dp2 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn2)), null, null);
        cb.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp1, dp2}));
    }

    private void addSan(JcaX509v3CertificateBuilder cb, String dns, String ips) throws Exception {
        List<GeneralName> names = new ArrayList<>();
        if (dns != null && !"null".equals(dns) && !dns.isEmpty()) {
            for (String d : dns.split(",")) {
                names.add(new GeneralName(GeneralName.dNSName, d.trim()));
            }
        }
        if (ips != null && !"null".equals(ips) && !ips.isEmpty()) {
            for (String ip : ips.split(",")) {
                InetAddress addr = InetAddress.getByName(ip.trim());
                names.add(new GeneralName(GeneralName.iPAddress,
                        new DEROctetString(addr.getAddress())));
            }
        }
        if (!names.isEmpty()) {
            GeneralName[] arr = names.toArray(new GeneralName[0]);
            cb.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(arr));
        }
    }

    /**
     * 构建 CPS 证书策略扩展（参考 smplus：CertificatePolicies + PolicyInformation + PolicyQualifierInfo 标准类）。
     * oids[0] 带 CPS URI + UserNotice 限定符，oids[1..] 为纯 OID 策略。
     */
    private CertificatePolicies buildCpsPolicies(String[] oids, String cpsUrl,
                                                 String cpsText) throws Exception {
        if (cpsUrl == null || cpsUrl.isEmpty() || "null".equalsIgnoreCase(cpsUrl)) {
            cpsUrl = "https://gitee.com/wxgshuju/modpkica";
        }
        if (cpsText == null || "null".equalsIgnoreCase(cpsText)) {
            cpsText = "";
        }
        java.util.List<PolicyInformation> infos = new java.util.ArrayList<>();

        // 第一个策略：OID + CPS URI + UserNotice 限定符
        java.util.List<PolicyQualifierInfo> qs = new java.util.ArrayList<>();
        qs.add(new PolicyQualifierInfo(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.1"),
                new DERIA5String(cpsUrl)));
        // UserNotice：explicitText 是 DisplayText CHOICE，直接放 UTF8String
        // （不能用 [0] EXPLICIT 包裹，否则权威解析工具 UserNotice.getInstance 报 DLTaggedObject）
        ASN1EncodableVector unV = new ASN1EncodableVector();
        unV.add(new DERUTF8String(cpsText));
        qs.add(new PolicyQualifierInfo(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"),
                new DERSequence(unV)));
        infos.add(new PolicyInformation(new ASN1ObjectIdentifier(oids[0]),
                new DERSequence(qs.toArray(new PolicyQualifierInfo[0]))));

        // 其余策略：纯 OID
        for (int i = 1; i < oids.length; i++) {
            infos.add(new PolicyInformation(new ASN1ObjectIdentifier(oids[i]), null));
        }
        return new CertificatePolicies(infos.toArray(new PolicyInformation[0]));
    }

    /**
     * 构建证书构建器并添加全部扩展（CPS 策略 / AIA / CRL / SAN / EKU / 专属扩展）。
     *
     * @param addPoison true = RFC 6962 §3.1 poison 扩展（critical，extnValue = OCTET STRING 05 00）
     *                  —— 仅用于 SCT 预证书；false = 普通证书
     */
    private JcaX509v3CertificateBuilder buildCertBuilder(X500Name issuer, BigInteger serial,
            Date notBefore, Date notAfter, X500Name subject,
            java.security.PublicKey pubKey, boolean isCa, Integer pathLen, int keyUsage,
            byte[] issuerSki, byte[] userSki,
            List<KeyPurposeId> eku, List<ASN1ObjectIdentifier> unknownEku,
            boolean isTsa, boolean isOcsp, String ocspUrl, String crtUrl, String crlUrl,
            CertificatePolicies certPolicies, String dns, String ips,
            boolean addPoison) throws Exception {
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, pubKey);
        BasicConstraints bc = (pathLen == null) ? new BasicConstraints(isCa)
                : new BasicConstraints(pathLen.intValue());
        cb.addExtension(Extension.basicConstraints, true, bc);
        if (keyUsage != 0) {
            cb.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        }
        cb.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(issuerSki));
        cb.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(userSki));
        if (!eku.isEmpty() || !unknownEku.isEmpty()) {
            cb.addExtension(Extension.extendedKeyUsage, isTsa,
                    ExtendedKeyUsage.getInstance(buildEkuSequence(eku, unknownEku)));
        }
        addAuthorityInfoAccess(cb, ocspUrl, crtUrl);
        addCrlDistributionPoints(cb, crlUrl);
        cb.addExtension(Extension.certificatePolicies, false, certPolicies);
        addSan(cb, dns, ips);
        // initOCSP 专属扩展：OCSP 不撤销检查（1.3.6.1.5.5.7.48.1.5 = 05 00）
        if (isOcsp) {
            cb.addExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.5"), false,
                    new DEROctetString(new byte[]{0x05, 0x00}));
        }
        // RFC 6962 §3.1 poison：critical，extnValue = OCTET STRING 包含 ASN.1 NULL(05 00)
        if (addPoison) {
            cb.addExtension(new ASN1ObjectIdentifier(CtLog.OID_POISON), true,
                    new DEROctetString(DERNull.INSTANCE));
        }
        return cb;
    }
    // ===================== 输出 =====================

    private void writeOutputs(X509Certificate cert, KeyPair kp, String algo, String serialHex,
                              boolean isCa, boolean isOcsp, boolean isTsa, String issuerId,
                              String tsaHash) throws Exception {
        String rootDir = baseDir + "/PKI/ROOT/";
        String caDir = baseDir + "/PKI/CA/";
        String certDir = baseDir + "/PKI/CERT/";
        String keyDir = baseDir + "/PKI/KEY/";
        String webDir = baseDir + "/PKI/WebPublic/CRT/";
        String ocspDir = baseDir + "/PKI/OCSP/";
        String tsaDir = baseDir + "/PKI/TIMSTAMP/";

        if (isTsa) {
            String base = tsaDir + algo.toLowerCase(Locale.ROOT) + "_" + tsaHash.toLowerCase(Locale.ROOT);
            // 重跑时先删除旧登记与旧 WebPublic 副本
            if (java.nio.file.Files.exists(java.nio.file.Paths.get(base + ".crt"))) {
                X509Certificate old = PemIO.readCert(base + ".crt");
                String oldSerial = old.getSerialNumber().toString(16);
                removeCertsLine(oldSerial);
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(webDir + oldSerial + ".crt"));
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(certDir + oldSerial + ".crt"));
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(keyDir + oldSerial + ".key"));
            }
            PemIO.writeCert(base + ".crt", cert);
            PemIO.writePrivateKey(base + ".key", kp.getPrivate(), algo);
            // TSA 证书同样按 序列号.crt 同步到 WebPublic/CRT
            PemIO.writeCert(webDir + serialHex + ".crt", cert);
            // 终端证书副本：PKI/CERT/{序列号}.crt 与 PKI/KEY/{序列号}.key
            PemIO.writeCert(certDir + serialHex + ".crt", cert);
            PemIO.writePrivateKey(keyDir + serialHex + ".key", kp.getPrivate(), algo);
            out("TSA专用证书生成成功！" + base + ".crt");
        } else if (isOcsp) {
            // 多根模型：OCSP 签名证书统一 序列号_ocsp.crt/.key
            String ocspBase = issuerId + "_ocsp";
            if (java.nio.file.Files.exists(java.nio.file.Paths.get(ocspDir + ocspBase + ".crt"))) {
                X509Certificate old = PemIO.readCert(ocspDir + ocspBase + ".crt");
                String oldSerial = old.getSerialNumber().toString(16);
                removeCertsLine(oldSerial);
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(webDir + oldSerial + ".crt"));
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(certDir + oldSerial + ".crt"));
                java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(keyDir + oldSerial + ".key"));
            }
            PemIO.writeCert(ocspDir + ocspBase + ".crt", cert);
            PemIO.writePrivateKey(ocspDir + ocspBase + ".key", kp.getPrivate(), algo);
            // OCSP 证书同样按 序列号.crt 同步到 WebPublic/CRT
            PemIO.writeCert(webDir + serialHex + ".crt", cert);
            // 终端证书副本：PKI/CERT/{序列号}.crt 与 PKI/KEY/{序列号}.key
            PemIO.writeCert(certDir + serialHex + ".crt", cert);
            PemIO.writePrivateKey(keyDir + serialHex + ".key", kp.getPrivate(), algo);
            out("OCSP专用证书生成成功！" + ocspDir + ocspBase + ".crt");
        } else {
            if (isCa) {
                PemIO.writeCert(caDir + serialHex + ".crt", cert);
                PemIO.writePrivateKey(caDir + serialHex + ".key", kp.getPrivate(), algo);
                out("中间CA证书生成成功！");
            } else {
                PemIO.writeCert(certDir + serialHex + ".crt", cert);
                PemIO.writePrivateKey(keyDir + serialHex + ".key", kp.getPrivate(), algo);
                out("用户证书生成成功！");
            }
            PemIO.writeCert(webDir + serialHex + ".crt", cert);
        }

        // CERTS.txt 登记
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = new CertsDB.CertEntry();
        e.serial = serialHex;
        e.type = isCa ? 'C' : 'E';
        e.status = 'V';
        e.reason = 0;
        e.time = LocalDateTime.now(); // 登记时间=当前真实签发时间
        e.issuerId = issuerId; // 实际用颁发者序列号
        e.algo = algo;
        db.addEntry(e);
    }

    /** 从 CERTS.txt 删除指定序列号行（重跑替换旧登记）。
     *  保留 # 注释/空行（与 CertsDB 语义一致）；PemIO.atomicWrite 原子替换，
     *  避免 TSA/OCSP 重跑时并发或中断导致 CERTS.txt 半截。 */
    private synchronized void removeCertsLine(String serial) throws Exception {
        java.nio.file.Path p = java.nio.file.Paths.get(baseDir + "/PKI/CERTS.txt");
        if (!java.nio.file.Files.exists(p)) {
            return;
        }
        List<String> lines = java.nio.file.Files.readAllLines(p,
                java.nio.charset.StandardCharsets.UTF_8);
        List<String> out = new ArrayList<>();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                out.add(line);
                continue;
            }
            String[] f = t.split("\\s+");
            if (f.length > 0 && f[0].equals(serial)) {
                continue;
            }
            out.add(line);
        }
        while (!out.isEmpty() && out.get(out.size() - 1).trim().isEmpty()) {
            out.remove(out.size() - 1);
        }
        String text = String.join("\n", out) + "\n";
        PemIO.atomicWrite(p, text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    // ===================== 工具 =====================

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static byte[] slice(byte[] a, int from, int len) {
        byte[] r = new byte[len];
        System.arraycopy(a, from, r, 0, len);
        return r;
    }

    private static byte[] longTo8Bytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (v & 0xFF);
            v >>= 8;
        }
        return b;
    }

    private static boolean contains(byte[] a, byte target) {
        for (byte x : a) {
            if (x == target) {
                return true;
            }
        }
        return false;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
