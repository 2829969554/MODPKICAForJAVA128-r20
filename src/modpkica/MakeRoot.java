package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
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
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;

/**
 * MakeRoot —— 生成根证书（对应 Go 版 cmd/makeroot）。
 *
 * <p>用法：{@code java -cp ... modpkica.MakeRoot "CN=xxx,O=yyy,..." &lt;密钥位数&gt; &lt;哈希&gt; &lt;算法&gt;}
 *
 * <ul>
 *   <li>DN 参数：逗号分隔的 {@code key=value}，支持 SERIALNUMBER/CN/O/OU/C/L/S/STREET/PostalCode，
 *       {@code %} 会替换为空格（与 Go 版一致）；</li>
 *   <li>密钥位数：RSA 1024~8192，ECC 224/256/384/521，SM2 固定 256；</li>
 *   <li>哈希：sha1 / sha256 / sha384 / sha512（RSA/ECC）；SM2 固定 SM3；</li>
 *   <li>算法：RSA / ECC / SM2。</li>
 * </ul>
 *
 * <p>输出（与 Go 版完全一致）：
 * <pre>
 *   PKI/ROOT/序列号.crt + 序列号.key（多根模型，不生成 root.crt/root.key）
 *   PKI/ROOT/序列号.crt + 序列号.key
 *   PKI/CERT/序列号.crt
 *   PKI/KEY/序列号.key
 *   PKI/WebPublic/CRT/序列号.crt
 * </pre>
 * 并向 CERTS.txt 追加一行根证书记录（类型 R，颁发者=自身）。
 */
public final class MakeRoot {

    /** 证书生效时间（Go 版固定值） */
    private static final String NOT_BEFORE = "2001-07-19 15:30:00";
    /** 证书过期时间（Go 版固定值） */
    private static final String NOT_AFTER = "2099-07-19 15:30:00";

    /** 生成 128 位安全随机正序列号（十六进制小写，查 CERTS.txt 去重）。 */
    private static BigInteger buildSerial(String baseDir) {
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        java.util.Set<String> used = existingSerials(baseDir);
        BigInteger serial;
        do {
            serial = new BigInteger(128, rnd);
        } while (serial.signum() <= 0 || used.contains(serial.toString(16)));
        return serial;
    }

    /** 读取 CERTS.txt 中已登记的序列号集合（十六进制小写），避免新序列号碰撞。 */
    private static java.util.Set<String> existingSerials(String baseDir) {
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
                    String[] parts = line.split("\s+");
                    if (parts.length >= 1) {
                        used.add(parts[0].toLowerCase());
                    }
                }
            }
        } catch (Exception ignored) {
            // 读不到视为空集合，随机序列号碰撞概率可忽略
        }
        return used;
    }

    private MakeRoot() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("用法: MakeRoot \"DN(逗号分隔key=value)\" 密钥位数 哈希 算法 [oid版本]");
            System.out.println("示例: MakeRoot \"CN=Test Root CA,O=My Org,C=CN\" 2048 sha256 RSA old");
            System.out.println("      oid版本可选：old=1.3.6.1.4.1.57264.1.8（缺省，SC27-2019） / new=2.23.140.3.1（EVG 2.0.1）");
            return;
        }
        run(AppPaths.baseDir(), args);
    }

    /** 供 ADMIN 内部调用：指定工作目录签发根证书。 */
    public static void run(String baseDir, String[] args) throws Exception {
        // Go 版 os.Args 含程序名，Java 不含：args[0]=DN args[1]=bit args[2]=hash args[3]=alg
        String dn = args[0];
        String hash = args[2];
        String keyType = args[3].toUpperCase(Locale.ROOT);

        // 密钥位数归一化（与 Go 版一致）
        int bit = parseKeyBits(args[1], keyType);

        Config cfg = new Config(baseDir);

        // ---- 1. 生成密钥对 ----
        KeyPair kp;
        switch (keyType) {
            case "RSA":
            case "RSA-PSS":
                kp = CertUtil.generateRsaKeyPair(bit);
                break;
            case "ECC":
                kp = CertUtil.generateEccKeyPair(bit);
                break;
            case "SM2":
                kp = CertUtil.generateSm2KeyPair();
                break;
            case "PQC":
                // ML-DSA-44/65/87：密钥位数参数为规格字符串（如 ML-DSA-65）
                kp = CertUtil.generatePqcKeyPair(args[1]);
                break;
            case "DSA":
                kp = CertUtil.generateDsaKeyPair(bit);
                break;
            case "EDDSA":
                // Ed25519（RFC 8032）：固定 256 位，无密钥位数参数
                kp = CertUtil.generateEd25519KeyPair();
                break;
            default:
                System.out.println("不支持的算法: " + keyType);
                return;
        }

        // ---- 2. 序列号 / 有效期 ----
        // 128 位密码学安全随机正整数（避免同秒/并发签发碰撞），与 MakeCert.buildSerial 一致
        BigInteger serial = buildSerial(baseDir);
        Date notBefore = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(NOT_BEFORE);
        Date notAfter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(NOT_AFTER);

        // ---- 3. 构建根证书 ----
        X500Name subject = buildSubject(dn);
        ContentSigner signer = CertUtil.createContentSigner(kp.getPrivate(), keyType, hash);
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());

        // ---- 3b. CABF Organization Identifier 扩展（EVG 9.2.8：subject 含 2.5.4.97 时必须带此扩展） ----
        String orgId = getDnField(dn, "2.5.4.97");
        if (orgId != null && !orgId.isEmpty()) {
            // 第 5 参数（可选）为扩展 OID 版本：new=2.23.140.3.1（EVG 2.0.1），缺省/old=1.3.6.1.4.1.57264.1.8（SC27-2019）
            String orgOid = args.length > 4 && "new".equalsIgnoreCase(args[4].trim())
                    ? CABF_ORG_ID_OID_NEW : CABF_ORG_ID_OID_OLD;
            addCABFOrganizationIdentifier(cb, orgId, orgOid);
        }

        // KeyUsage: digitalSignature(Go 1) | contentCommitment(Go 2) | keyCertSign(Go 32) | cRLSign(Go 64)
        // BC 位定义与 Go 不同，必须用 BC 常量：128|64|4|2
        cb.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                        | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // BasicConstraints: 根 CA，无 pathLen 限制（对齐 Go 版，允许下级再签中间 CA）
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // SKI = SHA1(subjectPublicKey)；自签根 AKI = SKI
        byte[] ski = CertUtil.getSubjectKeyIdentifier(kp.getPublic());
        cb.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        cb.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(ski));

        // ---- 4. AIA（OCSP + caIssuers）与 CRL 分发点（{CID} 替换为序列号） ----
        String serialHex = serial.toString(16);
        String ocspUrl = cfg.getOcspUrl();
        String crtUrl = cfg.getCrtUrl().replace("{CID}", serialHex);
        String crlUrl = cfg.getCrlUrl().replace("{CID}", serialHex);
        addAuthorityInfoAccess(cb, ocspUrl, crtUrl);
        addCrlDistributionPoints(cb, crlUrl);

        // ---- 5. CPS 证书策略扩展（2.5.29.32，结构对齐 Go 版 internal/cps） ----
        String cpsUrl = cfg.getCps();
        String cpsText = cfg.getCpsNonice();
        if (cpsUrl == null || cpsUrl.isEmpty() || "null".equalsIgnoreCase(cpsUrl)) {
            cpsUrl = "https://gitee.com/wxgshuju/modpkica";
        }
        if (cpsText == null || cpsText.isEmpty() || "null".equalsIgnoreCase(cpsText)) {
            cpsText = "我是受信任证书颁发机构签发的可信根证书。\nThis is a Trusted Root Certificate Authority.";
        }
        // CONFIG 中字面 \n 转真实换行（配置页以单行 \n 存储，证书内需真实换行）
        cpsText = cpsText.replace("\\n", "\n");
        cb.addExtension(new ASN1ObjectIdentifier("2.5.29.32"), false,
                buildCpsPolicies(cpsUrl, cpsText));

        // ---- 6. 生成并写出 ----
        X509CertificateHolder holder = cb.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(holder);

        String rootDir = baseDir + "/PKI/ROOT/";
        String webDir = baseDir + "/PKI/WebPublic/CRT/";

        // R 类型目录规则：ROOT/序列号.crt|.key + WebPublic/CRT/序列号.crt（不写 CERT/KEY）
        PemIO.writeCert(rootDir + serialHex + ".crt", cert);
        PemIO.writeCert(webDir + serialHex + ".crt", cert);
        PemIO.writePrivateKey(rootDir + serialHex + ".key", kp.getPrivate(), keyType);

        // ---- 7. 追加 CERTS.txt 记录（登记时间=当前真实签发时间） ----
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = new CertsDB.CertEntry();
        e.serial = serialHex;
        e.type = 'R';
        e.status = 'V';
        e.reason = 0;
        e.time = LocalDateTime.now();
        e.issuerId = serialHex; // 根证书颁发者=自身
        e.algo = keyType;
        db.addEntry(e);

        System.out.println("根证书生成成功 序列号=" + serialHex + " 算法=" + keyType
                + " 位长=" + ("PQC".equals(keyType) ? CertUtil.normalizePqcSpec(args[1]) : bit)
                + " 哈希=" + hash);

        // ---- 8. 生成该根的 CRL（对齐 Go 版：MAKEROOT 完成后调用 rootGETcrl；baseDir 必须贯穿，PKI-031） ----
        RootGetCrl.run(baseDir);
    }

    /**
     * 解析并归一化密钥位数（规则与 Go 版完全一致）。
     */
    private static int parseKeyBits(String arg, String keyType) {
        int bit;
        try {
            bit = Integer.parseInt(arg.trim());
        } catch (NumberFormatException ex) {
            bit = 0;
        }
        if ("RSA".equals(keyType) || "RSA-PSS".equals(keyType)) {
            if (bit < 1024) {
                bit = 2048; // 缺省
            }
            if (bit < 1024) {
                bit = 1024;
            }
            return bit;
        }
        if ("ECC".equals(keyType)) {
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
        if ("PQC".equals(keyType)) {
            return 0; // ML-DSA 规格字符串（ML-DSA-44/65/87）由 generatePqcKeyPair 处理
        }
        if ("DSA".equals(keyType)) {
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
        if ("EDDSA".equalsIgnoreCase(keyType)) {
            return 256; // Ed25519 固定 256
        }
        return 256; // SM2 固定 256
    }

    /**
     * 解析 DN 字符串为 X500Name（RDN 顺序对齐 Go 版 pkix.Name：C,O,OU,L,S,STREET,PostalCode,SERIALNUMBER,CN）。
     */
    private static X500Name buildSubject(String dn) {
        X500NameBuilder builder = new X500NameBuilder();
        java.util.Map<String, String> fields = new java.util.LinkedHashMap<>();
        for (String part : dn.split(",")) {
            String p = part.trim();
            int idx = p.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = p.substring(0, idx).trim();
            String value = p.substring(idx + 1).trim().replace("%", " ");
            if (value.isEmpty()) {
                continue;
            }
            fields.put(key, value);
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

    private static void addIfPresent(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isEmpty()) {
            builder.addRDN(oid, value);
        }
    }

    /**
     * 添加 AuthorityInfoAccess 扩展（OCSP + caIssuers）。
     */
    private static void addAuthorityInfoAccess(JcaX509v3CertificateBuilder cb,
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

    /**
     * 添加 CRL 分发点扩展（含 .crl 与 .der.crl 两个 URL，对齐 Go 版）。
     */
    private static void addCrlDistributionPoints(JcaX509v3CertificateBuilder cb, String crlUrl)
            throws Exception {
        if (crlUrl == null || crlUrl.isEmpty()) {
            return;
        }
        String url1 = crlUrl;
        String url2 = crlUrl.replace(".crl", ".der.crl");
        GeneralName gn1 = new GeneralName(GeneralName.uniformResourceIdentifier, url1);
        GeneralName gn2 = new GeneralName(GeneralName.uniformResourceIdentifier, url2);
        DistributionPoint dp1 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn1)), null, null);
        DistributionPoint dp2 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn2)), null, null);
        cb.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp1, dp2}));
    }

    /*
     * CABF Organization Identifier 扩展 OID。
     *
     * 2019 SC27 ballot 曾使用 IANA 57264 arc：1.3.6.1.4.1.57264.1.8；
     * 最新 EVG 2.0.1 / BR 已将扩展迁移到 CA/B Forum 自有 arc：2.23.140.3.1。
     * 两者 ASN.1 结构相同；依赖方按旧 OID 校验请保持现状，如需新版改此常量即可。
     */
    /** 旧版扩展 OID：2019 SC27 ballot（CABF IANA 57264 arc）。 */
    private static final String CABF_ORG_ID_OID_OLD = "1.3.6.1.4.1.57264.1.8";
    /** 新版扩展 OID：EVG 2.0.1 / BR（CA/B Forum 自有 arc 2.23.140.3.1）。 */
    private static final String CABF_ORG_ID_OID_NEW = "2.23.140.3.1";

    /** 从逗号分隔 DN 中提取指定 key（标准名或 OID）的值，未找到返回 null。 */
    private static String getDnField(String dn, String key) {
        for (String part : dn.split(",")) {
            String p = part.trim();
            int idx = p.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String k = p.substring(0, idx).trim();
            if (k.equalsIgnoreCase(key)) {
                return p.substring(idx + 1).trim().replace("%", " ");
            }
        }
        return null;
    }

    /**
     * 生成 CABF Organization Identifier 扩展（EVG 7.1.2.2）。
     *
     * <p>subject:organizationIdentifier (2.5.4.97) 的值格式（EVG 7.1.4.2.8）：
     * <pre>
     *   {注册方案标识符 3字符}{国家码 2字符}[+{州省码 1-2字符}]-{注册参考号}
     *   例：NTRGB-12345678、NTRUS+CA-12345678、VATDE-123456789、PSDBE-NBB-1234.567.890
     * </pre>
     * 最左侧连字符为分隔符，其余连字符属于注册参考号。
     * 扩展 ASN.1：
     * <pre>
     *   CABFOrganizationIdentifier ::= SEQUENCE {
     *       registrationSchemeIdentifier  PrintableString (SIZE(3)),
     *       registrationCountry           PrintableString (SIZE(2)),
     *       registrationStateOrProvince   [0] IMPLICIT PrintableString (SIZE(0..128)) OPTIONAL,
     *       registrationReference         UTF8String
     *   }
     * </pre>
     * 注册方案按 EVG 附录 H 目前仅 NTR / VAT / PSD 获认可；此处宽松接受任意 3 字符字母方案。
     */
    private static void addCABFOrganizationIdentifier(JcaX509v3CertificateBuilder cb, String orgId,
                                                       String extOid) {
        try {
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("^([A-Za-z]{3})([A-Za-z]{2})(?:\\+([A-Za-z0-9]{1,2}))?-([\\s\\S]+)$")
                    .matcher(orgId.trim());
            if (!m.matches()) {
                System.out.println("警告: organizationIdentifier 格式不符合 EVG 7.1.4.2.8"
                        + "（应如 NTRGB-12345678 / VATDE-123456789 / NTRUS+CA-12345678），"
                        + "跳过 CABF Organization Identifier 扩展: " + orgId);
                return;
            }
            String scheme = m.group(1).toUpperCase(Locale.ROOT);
            String country = m.group(2).toUpperCase(Locale.ROOT);
            String state = m.group(3); // 可为 null
            String reference = m.group(4);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new org.bouncycastle.asn1.DERPrintableString(scheme));
            v.add(new org.bouncycastle.asn1.DERPrintableString(country));
            if (state != null && !state.isEmpty()) {
                v.add(new DERTaggedObject(false, 0,
                        new org.bouncycastle.asn1.DERPrintableString(state.toUpperCase(Locale.ROOT))));
            }
            v.add(new DERUTF8String(reference));
            cb.addExtension(new ASN1ObjectIdentifier(extOid), false, new DERSequence(v));
            System.out.println("已生成 CABF Organization Identifier 扩展: scheme=" + scheme
                    + " country=" + country
                    + (state != null ? " stateOrProvince=" + state.toUpperCase(Locale.ROOT) : "")
                    + " reference=" + reference);
        } catch (Exception ex) {
            System.out.println("警告: 生成 CABF Organization Identifier 扩展失败: " + ex.getMessage());
        }
    }

    /**
     * 构建 CPS 证书策略扩展值（OID 2.5.29.32）。
     *
     * <p>结构与 Go 版 internal/cps/cps.go GenerateCPSbyte 一致：
     * <pre>
     *   SEQUENCE {
     *     SEQUENCE { 1.3.6.1.4.1.4146.1.95,
     *       SEQUENCE { 1.3.6.1.5.5.7.2.1, IA5String(cpsUrl) },
     *       SEQUENCE { 1.3.6.1.5.5.7.2.2, SEQUENCE { UTF8String(文本) } }
     *     },
     *     SEQUENCE { 2.5.29.32.0 },
     *     SEQUENCE { 1.3.6.1.4.1.311.10.12.1 },
     *     SEQUENCE { 2.23.140.1.1 },
     *     SEQUENCE { 2.23.140.1.3 }
     *   }
     * </pre>
     * 注意：explicitText 是 DisplayText CHOICE，直接放 UTF8String；
     * 不能用 [0] EXPLICIT 包裹，否则权威解析工具 UserNotice.getInstance 报 DLTaggedObject。
     */
    private static org.bouncycastle.asn1.ASN1Primitive buildCpsPolicies(String cpsUrl, String cpsText)
            throws Exception {
        // UserNotice ::= SEQUENCE { explicitText UTF8String }
        ASN1EncodableVector userNoticeVec = new ASN1EncodableVector();
        userNoticeVec.add(new DERUTF8String(cpsText));
        DERSequence userNotice = new DERSequence(userNoticeVec);

        // 第一个 PolicyInformation：策略 OID + CPS URI + UserNotice
        ASN1EncodableVector qualifiers = new ASN1EncodableVector();
        ASN1EncodableVector cpsQualifier = new ASN1EncodableVector();
        cpsQualifier.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.1"));
        cpsQualifier.add(new DERIA5String(cpsUrl));
        qualifiers.add(new DERSequence(cpsQualifier));

        ASN1EncodableVector unQualifier = new ASN1EncodableVector();
        unQualifier.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"));
        unQualifier.add(userNotice);
        qualifiers.add(new DERSequence(unQualifier));

        ASN1EncodableVector firstPolicy = new ASN1EncodableVector();
        firstPolicy.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.4146.1.95"));
        firstPolicy.add(new DERSequence(qualifiers));

        ASN1EncodableVector policies = new ASN1EncodableVector();
        policies.add(new DERSequence(firstPolicy));
        // 其余纯 OID 策略项
        String[] extraOids = {"2.5.29.32.0", "1.3.6.1.4.1.311.10.12.1", "2.23.140.1.1", "2.23.140.1.3"};
        for (String oid : extraOids) {
            ASN1EncodableVector p = new ASN1EncodableVector();
            p.add(new ASN1ObjectIdentifier(oid));
            policies.add(new DERSequence(p));
        }
        return new DERSequence(policies);
    }
}
