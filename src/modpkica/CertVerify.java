package modpkica;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CERTVERIFY —— 证书验证工具（对应 Go 版 cmd/certverify）。
 *
 * <p>用法：{@code CERTVERIFY 证书文件或序列号}。参数不含点号时自动从
 * PKI/WebPublic/CRT/序列号.crt 读取；否则按给定路径读取。
 *
 * <p>功能：
 * <ul>
 *   <li>解析并打印证书关键信息（版本、序列号、签名算法、颁发者/使用者、有效期、公钥、
 *       SKI/AKI、EKU、SAN、AIA、CRL 分发点、密钥用法、基本约束、证书策略、扩展、签名）；</li>
 *   <li>签名验证：根证书自验；非根证书从 AIA 的 caIssuers URL 拉取颁发者证书后验证；
 *       打印证书链与信任状态；</li>
 *   <li>吊销状态：CRL（从 CRL 分发点拉取）+ OCSP（构造请求并 POST 到 OCSP URL）；</li>
 *   <li>打印密钥/证书的各种哈希（RFC-SHA1、Pin-SHA256、SHA1、SHA256、签名哈希）；</li>
 *   <li>SCT / CT 透明度扩展展示（含 MODPKICA 3 组 SCT 的签名验证）。</li>
 * </ul>
 */
public final class CertVerify {

    private CertVerify() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println(" 验证证书签名、证书状态、证书有效性\n 例如 CERTVERIFY cert.crt");
            return;
        }
        String filename = args[0];
        if (!filename.contains(".")) {
            // 无扩展名：按序列号从 WebPublic/CRT 读取（文件名统一小写，容忍用户输入大写）
            filename = AppPaths.baseDir() + "/PKI/WebPublic/CRT/" + filename.toLowerCase() + ".crt";
        }
        Path p = Paths.get(filename);
        if (!Files.exists(p)) {
            System.out.println("文件 " + filename + " 不存在");
            return;
        }
        run(p);
    }

    /** 供 ADMIN verifyCERT / WebAdmin /api/verify 内部调用。 */
    public static void run(String filename) throws Exception {
        if (filename == null || filename.isEmpty()) {
            System.out.println("目标为空，请输入证书文件路径或序列号");
            return;
        }
        if (!filename.contains(".")) {
            // 无扩展名：按序列号从 WebPublic/CRT 读取（文件名统一小写，容忍用户输入大写）
            String serial = filename.toLowerCase();
            filename = AppPaths.baseDir() + "/PKI/WebPublic/CRT/" + serial + ".crt";
        }
        Path p = Paths.get(filename);
        if (!Files.exists(p)) {
            System.out.println("文件 " + filename + " 不存在（如输入的是序列号，请确认 WebPublic/CRT/序列号.crt 存在）");
            return;
        }
        run(p);
    }

    /** 解析证书字节：自动识别 PEM / DER。 */
    private static X509Certificate parseCert(byte[] data) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data));
    }

    private static void run(Path p) throws Exception {
        Bc.init();
        byte[] certPem = Files.readAllBytes(p);
        X509Certificate cert = parseCert(certPem);

        // ---- 基本信息 ----
        System.out.println("        版本： " + (cert.getVersion()));
        String serialHex = cert.getSerialNumber().toString(16);
        if (serialHex.length() % 2 != 0) {
            serialHex = "0" + serialHex;
        }
        System.out.println("      序列号： " + serialHex);
        String[] ht = getHashType(cert);
        System.out.println("    签名算法： " + sigAlgDisplay(cert.getSigAlgName()) + " (" + cert.getSigAlgOID() + ")");
        System.out.println("签名哈希算法： " + ht[0] + "\n");
        System.out.println("颁发者： " + cert.getIssuerX500Principal());
        System.out.println("有效期从： " + cert.getNotBefore());
        System.out.println("有效期到： " + cert.getNotAfter() + "\n");
        System.out.println("使用者： " + cert.getSubjectX500Principal());

        // ---- 公钥 ----
        PublicKey pub = cert.getPublicKey();
        String keyInfo = describePublicKey(pub);
        System.out.println("    公钥： " + keyInfo);

        // ---- SKI/AKI（纯净值，剥离 ASN.1 包装，对齐 Go 版显示） ----
        byte[] ski = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        byte[] aki = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        System.out.println("授权密钥标识符  ： " + (aki == null ? "" : hex(authorityKeyIdValue(aki))));
        System.out.println("使用者密钥标识符： " + (ski == null ? "" : hex(subjectKeyIdValue(ski))) + "\n");

        // ---- EKU ----
        printExtKeyUsage(cert);

        // ---- SAN ----
        printSan(cert);

        // ---- AIA / CRL ----
        printAiaAndCrl(cert);

        // ---- KeyUsage / BasicConstraints ----
        boolean[] kuArr = cert.getKeyUsage();
        System.out.println("密钥用法： " + (kuArr != null ? bitsToString(kuArr) : "无"));
        if (cert.getBasicConstraints() >= 0) {
            System.out.println("基本约束(关键)：\n              Subject Type="
                    + (cert.getBasicConstraints() > 0 ? "CA" : "End Entity")
                    + "  Path Length Constraint = " + cert.getBasicConstraints());
        }

        // ---- 证书策略 ----
        printPolicies(cert);

        // ---- 扩展（未知 OID 原样打印） ----
        printExtensions(cert);

        System.out.println("\n\n");
        System.out.println("证书签名：\n        " + hex(cert.getSignature()) + "\n");

        // ---- 签名验证与证书链 ----
        boolean isRoot = cert.getSubjectX500Principal().getName()
                .equals(cert.getIssuerX500Principal().getName());
        boolean signOk;
        if (isRoot) {
            System.out.println("证书类别： 根证书\n");
            signOk = verifySignature(cert, cert.getPublicKey());
            if (signOk) {
                System.out.println("验证签名： 成功（根证书自验证通过）");
            } else {
                System.out.println("验证签名： 失败");
            }
            // 实验 TrustAnchor：自签名有效 ≠ 属于当前环境的信任锚
            // （PKI/ROOT/*.crt 中存在该证书公钥才算可信）
            if (signOk && isInTrustAnchor(cert)) {
                System.out.println("信任状态： 可信 (此证书已通过信任锚[Root根证书]的验证)\n");
            } else if (signOk) {
                System.out.println("信任状态： 不可信 (自签名有效，但不在实验信任锚 PKI/ROOT 中)\n");
            } else {
                System.out.println("信任状态： 不可信 (自签名验证失败)\n");
            }
        } else {
            System.out.println("证书类别： 非根证书\n");
            System.out.println("证书链： ");
            X509Certificate issuer = fetchIssuer(cert);
            if (issuer == null) {
                System.out.println("验证签名： 无法验证签名 |无法找到上级证书链~ ");
            } else {
                signOk = verifySignature(cert, issuer.getPublicKey());
                System.out.println("验证签名： " + (signOk ? "通过、签名有效" : "失败")
                        + " 颁发者=" + issuer.getSubjectX500Principal());
            }
        }

        // ---- 吊销状态 ----
        System.out.print("证书状态：");
        Date now = new Date();
        if (now.before(cert.getNotBefore())) {
            System.out.println("该证书尚未生效。");
        } else {
            checkCrl(cert);
            checkOcsp(cert);
        }

        // ---- 各种哈希 ----
        printHashes(cert, pub);
    }

    // ============================================================
    // 信息打印
    // ============================================================

    /** JCA 签名算法名转 Go 风格显示（SHA256WITHRSA → SHA256-RSA、SHA256WITHECDSA → SHA256-ECDSA）。 */
    private static String sigAlgDisplay(String jcaName) {
        String s = jcaName == null ? "" : jcaName.replace("WITHRSA", "-RSA")
                .replace("WITHECDSA", "-ECDSA")
                .replace("WITH", "-")
                .replace("_", "");
        return s.isEmpty() ? (jcaName == null ? "" : jcaName) : s;
    }

    private static String[] getHashType(X509Certificate cert) {
        // RSASSA-PSS：BC 的 getSigAlgName() 通常为 "RSASSA-PSS"，须从签名参数解析哈希
        if ("1.2.840.113549.1.1.10".equals(cert.getSigAlgOID())) {
            return new String[]{pssHashName(cert), "RSA"};
        }
        return getHashType(cert.getSigAlgName());
    }

    private static String[] getHashType(String sigAlgName) {
        String upper = sigAlgName == null ? "" : sigAlgName.toUpperCase();
        if (upper.contains("SM2") || upper.contains("SM3")) {
            return new String[]{"SM3", "SM2"};
        }
        if (upper.contains("SHA512")) {
            return new String[]{"SHA512", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA384")) {
            return new String[]{"SHA384", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA256")) {
            return new String[]{"SHA256", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA1")) {
            return new String[]{"SHA1", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        return new String[]{"", ""};
    }

    private static String describePublicKey(PublicKey pub) {
        String alg = pub.getAlgorithm();
        if ("RSA".equalsIgnoreCase(alg)) {
            java.security.interfaces.RSAPublicKey rsa =
                    (java.security.interfaces.RSAPublicKey) pub;
            return "RSA " + rsa.getModulus().bitLength();
        }
        if ("EC".equalsIgnoreCase(alg) || "SM2".equalsIgnoreCase(alg)) {
            java.security.interfaces.ECPublicKey ec =
                    (java.security.interfaces.ECPublicKey) pub;
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            if (bits == 256 && alg.startsWith("SM") || alg.equals("SM2")) {
                return "SM2 256";
            }
            return "ECC " + bits;
        }
        return alg;
    }

    private static void printExtKeyUsage(X509Certificate cert) throws Exception {
        System.out.println("增强型密钥用法：\n");
        List<String> oids = cert.getExtendedKeyUsage();
        if (oids == null) {
            return;
        }
        for (String oid : oids) {
            System.out.println("              " + ekuName(oid) + " (" + oid + ")");
        }
    }

    private static String ekuName(String oid) {
        switch (oid) {
            // ---- 标准 EKU（1.3.6.1.5.5.7.3.*） ----
            case "1.3.6.1.5.5.7.3.1": return "服务器身份验证";
            case "1.3.6.1.5.5.7.3.2": return "客户端身份验证";
            case "1.3.6.1.5.5.7.3.3": return "代码签名";
            case "1.3.6.1.5.5.7.3.4": return "安全电子邮件";
            case "1.3.6.1.5.5.7.3.5": return "IP 安全终端系统";
            case "1.3.6.1.5.5.7.3.6": return "IP 安全隧道终止";
            case "1.3.6.1.5.5.7.3.7": return "IP 安全用户";
            case "1.3.6.1.5.5.7.3.8": return "时间戳";
            case "1.3.6.1.5.5.7.3.9": return "OCSP 签名";
            case "1.3.6.1.4.1.311.10.3.3": return "微软服务器GatedCrypto";
            case "2.16.840.1.113730.4.1": return "Netscape服务器GatedCrypto";
            // ---- Windows / 微软扩展 EKU ----
            case "1.3.6.1.4.1.311.2.1.22": return "Windows 商业代码签名";
            case "1.3.6.1.4.1.311.10.3.5": return "Windows 硬件驱动程序验证";
            case "1.3.6.1.4.1.311.10.3.6": return "Windows 系统组件验证";
            case "1.3.6.1.4.1.311.10.3.7": return "OEM Windows 系统组件验证";
            case "1.3.6.1.4.1.311.10.3.8": return "内嵌 Windows 系统组件验证";
            case "1.3.6.1.4.1.311.61.1.1": return "内核模式代码签名";
            case "1.3.6.1.4.1.311.64.1.1": return "域名系统(DNS)服务器信任";
            case "1.3.6.1.4.1.311.47.1.1": return "系统健康身份认证";
            case "1.3.6.1.4.1.311.10.3.19": return "已吊销列表签名者";
            case "1.3.6.1.5.2.3.5": return "KDC 身份认证";
            case "1.3.6.1.4.1.311.10.3.13": return "生存时间签名";
            case "1.3.6.1.4.1.311.21.5": return "私钥存档";
            case "2.5.29.32.0": return "所有颁发策略";
            case "1.3.6.1.4.1.311.10.121": return "所有颁发应用程序策略";
            case "1.3.6.1.4.1.311.10.3.10": return "合格部署";
            case "1.3.6.1.4.1.311.10.3.11": return "密钥恢复";
            case "1.3.6.1.4.1.311.10.3.12": return "文档签名";
            case "1.3.6.1.4.1.311.10.3.2": return "Microsoft 时间戳";
            case "1.3.6.1.4.1.311.10.3.4": return "加密文件系统";
            case "1.3.6.1.4.1.311.21.6": return "密钥恢复代理";
            case "1.3.6.1.4.1.311.21.19": return "目录服务电子邮件复制";
            case "1.3.6.1.5.5.8.2.2": return "IP 安全 IKE 中级";
            case "1.3.6.1.4.1.311.10.3.4.1": return "文件恢复";
            case "1.3.6.1.4.1.311.10.3.9": return "根列表签名者";
            case "1.3.6.1.4.1.311.10.5.1": return "数字权利";
            case "1.3.6.1.4.1.311.10.6.1": return "密钥数据包许可证";
            case "1.3.6.1.4.1.311.10.6.2": return "许可证服务器验证";
            case "1.3.6.1.4.1.311.20.1": return "CTL 用法";
            case "1.3.6.1.4.1.311.20.2.1": return "证书申请代理";
            case "1.3.6.1.4.1.311.20.2.2": return "智能卡登录";
            case "1.3.6.1.4.1.311.21.30": return "智能卡已验证";
            case "1.3.6.1.4.1.311.21.31": return "智能卡证书已验证";
            case "1.3.6.1.4.1.311.21.32": return "智能卡信任使用";
            // ---- Apple ----
            case "1.2.840.113635.100.4.1": return "Apple CodeSign 代码签名";
            case "1.2.840.113635.100.4.1.1": return "Apple Development CodeSign 开发者代码签名";
            case "1.2.840.113635.100.4.1.4": return "Apple Resource Signing 资源签名";
            case "1.2.840.113635.100.4.2": return "Apple Ichat Signing Ichat签名";
            case "2.5.29.37.0": return "任何目的";
            default: return oid;
        }
    }

    private static void printSan(X509Certificate cert) throws Exception {
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null || sans.isEmpty()) {
            return;
        }
        System.out.println("\n使用者可选名称：");
        for (List<?> san : sans) {
            int type = ((Number) san.get(0)).intValue();
            String value = String.valueOf(san.get(1));
            switch (type) {
                case 2: System.out.println("              DNS = " + value); break;
                case 1: System.out.println("              Email = " + value); break;
                case 7: System.out.println("              IP = " + value); break;
                default: System.out.println("              type" + type + " = " + value); break;
            }
        }
    }

    private static void printAiaAndCrl(X509Certificate cert) throws Exception {
        System.out.println("授权信息访问：");
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia != null) {
            org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                    org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(aia)));
            for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
                String name = ad.getAccessMethod().equals(
                        org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp)
                        ? "OCSP   URL" : "颁发者 URL";
                System.out.println("              " + name + "="
                        + ad.getAccessLocation().getName().toString());
            }
        }
        System.out.println("证书吊销列表：");
        byte[] crlExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExt != null) {
            org.bouncycastle.asn1.x509.CRLDistPoint cdp =
                    org.bouncycastle.asn1.x509.CRLDistPoint.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(crlExt)));
            for (org.bouncycastle.asn1.x509.DistributionPoint dp : cdp.getDistributionPoints()) {
                if (dp.getDistributionPoint() == null) {
                    continue;
                }
                org.bouncycastle.asn1.x509.GeneralNames gns =
                        org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                                dp.getDistributionPoint().getName());
                for (org.bouncycastle.asn1.x509.GeneralName gn : gns.getNames()) {
                    System.out.println("              CRL分发点 = " + gn.getName().toString());
                }
            }
        }
    }

    private static void printPolicies(X509Certificate cert) throws Exception {
        System.out.println("证书策略：");
        byte[] ext = cert.getExtensionValue(Extension.certificatePolicies.getId());
        if (ext == null) {
            return;
        }
        org.bouncycastle.asn1.x509.CertificatePolicies policies =
                org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(ext)));
        for (org.bouncycastle.asn1.x509.PolicyInformation pi : policies.getPolicyInformation()) {
            String oid = pi.getPolicyIdentifier().getId();
            System.out.println("              " + policyName(oid) + " OID = " + oid);
        }
    }

    private static String policyName(String oid) {
        switch (oid) {
            case "2.23.140.1.3": return "Extended Validation(扩展验证，代码签名)";
            case "2.23.140.1.4.1": return "Code Signing(代码签名)";
            case "2.23.140.1.4.2": return "TSA 证书(时间戳)";
            case "2.23.140.1.1": return "Extended Validation(扩展验证，SSL)";
            case "2.23.140.1.2.2": return "Organization Validation(组织验证)";
            case "2.23.140.1.2.1": return "Domain Validation(域名验证)";
            case "2.23.140.1.2.3": return "Individuals Validation(个人验证)";
            case "2.5.29.32.0": return "所有颁发策略";
            case "1.3.6.1.4.1.311.10.12.1": return "所有应用程序策略";
            case "1.3.6.1.5.5.7.2.1": return "证书实践声明指针(Practices Statement)";
            case "1.3.6.1.5.5.7.2.2": return "用户通告(User Notice)";
            default:
                // 对齐 Go 版：1.3.6.1.4.1 私用前缀的未知名 → 证书颁发策略(Statement Identifier)
                if (oid.startsWith("1.3.6.1.4.1.")) {
                    return "证书颁发策略(Statement Identifier)";
                }
                return "";
        }
    }

    /** 打印扩展（含 CT SCT 列表与 CT Log 公钥）。 */
    private static void printExtensions(X509Certificate cert) throws Exception {
        Set<String> critical = cert.getCriticalExtensionOIDs();
        for (String oid : cert.getNonCriticalExtensionOIDs() == null
                ? java.util.Collections.<String>emptySet()
                : cert.getNonCriticalExtensionOIDs()) {
            printOneExtension(cert, oid, false, critical != null && critical.contains(oid));
        }
        if (critical != null) {
            for (String oid : critical) {
                printOneExtension(cert, oid, true, true);
            }
        }
    }

    private static void printOneExtension(X509Certificate cert, String oid,
                                          boolean printed, boolean isCritical) throws Exception {
        byte[] value = unwrapOctets(cert.getExtensionValue(oid));
        if (oid.startsWith("1.3.6.1.4.1.11129.2.4.")) {
            // CT 扩展：单独展示
            if (oid.equals("1.3.6.1.4.1.11129.2.4.5")) {
                System.out.println("公钥列表:");
                byte[][] cs = chunks(value);
                for (byte[] c : cs) {
                    if (c.length == 0) {
                        continue;
                    }
                    System.out.println("         公钥标识符: " + hex(sha256(c)));
                    System.out.println("           签名公钥: " + hex(c));
                    System.out.println("");
                }
            } else if (oid.equals("1.3.6.1.4.1.11129.2.4.2")) {
                System.out.println("SCT列表:");
                printSctList(cert, value);
            }
            return;
        }
        // 对齐 Go 版 ShowPkixExtension：X.509 标准扩展（2. 开头）与 AIA 已在上方结构化展示，
        // 不再重复打印原始 hex
        if (oid.startsWith("2.") || oid.equals("1.3.6.1.5.5.7.1.1")) {
            return;
        }
        if (printed) {
            return;
        }
        System.out.println((isCritical ? "(关键) " : "") + oid + ":\n        " + hex(value) + "\n");
    }

    /**
     * 解析并打印 SCT 列表（RFC 6962 TLS 编码）。
     *
     * <p>结构（与权威解析工具 X509JsonConverter.parseSCTList/parseSCT 一致）：
     * SCTList = uint16 totalLen + [uint16 sctLen + SerializedSCT]*；
     * SerializedSCT = version(1) + log_id(32) + timestamp(8) +
     * extensions(uint16+data) + hash_alg(1) + sig_alg(1) + signature(uint16+data)。
     */
    private static void printSctList(X509Certificate cert, byte[] value) {
        // 验证环境：CT 日志公钥 + 颁发者（用于 precert_entry 验签）
        Map<String, String[]> logKeys = loadCtLogKeys();
        X509Certificate issuer = null;
        try {
            boolean selfIssued = cert.getSubjectX500Principal().getName()
                    .equals(cert.getIssuerX500Principal().getName());
            issuer = selfIssued ? cert : fetchIssuerSilent(cert);
        } catch (Exception ignore) {
        }
        byte[] issuerKeyHash = null;
        byte[] tbsNoSct = null;
        byte[] certDer = null;
        if (issuer != null) {
            try {
                issuerKeyHash = sha256(issuer.getPublicKey().getEncoded());
                tbsNoSct = tbsWithoutSctExt(cert);
                certDer = cert.getEncoded();
            } catch (Exception ignore) {
            }
        }
        // 扩展值是双重 OCTET STRING（BC addExtension 会再包一层；权威工具
        // X509JsonConverter 用 ext.getParsedValue() 解内层）。循环解开 0x04 外壳（最多 2 层）
        byte[] tls = value;
        for (int i = 0; i < 2 && tls != null && tls.length > 0 && (tls[0] & 0xff) == 0x04; i++) {
            byte[] inner = unwrapOctets(tls);
            if (inner == tls) {
                break;
            }
            tls = inner;
        }
        if (tls == null || tls.length < 2) {
            System.out.println(hex(value));
            return;
        }
        int totalLen = ((tls[0] & 0xff) << 8) | (tls[1] & 0xff);
        int pos = 2;
        int end = Math.min(pos + totalLen, tls.length);
        int no = 1;
        boolean parsedAny = false;
        while (pos + 2 <= end) {
            int sctLen = ((tls[pos] & 0xff) << 8) | (tls[pos + 1] & 0xff);
            pos += 2;
            if (sctLen < 47 || pos + sctLen > end) {
                break; // 结构异常，退出循环
            }
            int s = pos;
            int version = tls[s] & 0xff;
            byte[] logId = java.util.Arrays.copyOfRange(tls, s + 1, s + 33);
            long timestamp = 0;
            for (int i = 0; i < 8; i++) {
                timestamp = (timestamp << 8) | (tls[s + 33 + i] & 0xff);
            }
            int p = s + 41; // extensions 字段
            int extLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            byte[] extensions = extLen > 0
                    ? java.util.Arrays.copyOfRange(tls, p, p + extLen) : new byte[0];
            p += extLen;
            if (p + 4 > s + sctLen) {
                break;
            }
            int hash = tls[p++] & 0xff;
            int sigType = tls[p++] & 0xff;
            int sigLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            if (p + sigLen > s + sctLen) {
                break;
            }
            byte[] signature = java.util.Arrays.copyOfRange(tls, p, p + sigLen);
            System.out.println("      第 " + no + " 条 SCT:");
            System.out.println("        日志版本:  V" + (version + 1));
            String logDesc = "未知日志";
            if (logKeys != null) {
                String b64 = Base64.getEncoder().encodeToString(logId);
                String[] lk = logKeys.get(b64);
                if (lk != null && !lk[0].isEmpty()) {
                    logDesc = lk[0];
                }
            }
            System.out.println("        日志名称:  " + logDesc);
            System.out.println("      日志标识符:  " + hex(logId));
            System.out.println("          时间戳:  " + new Date(timestamp));
            if (extLen > 0) {
                System.out.println("        扩展数据:  " + hex(extensions));
            }
            System.out.println("        签名类型:  " + sigName(hash, sigType));
            System.out.println("            签名:  " + hex(signature));
            SctVerifyOutcome outcome = sctStatus(logId, version, timestamp,
                    extensions, hash, sigType, signature, logKeys, issuer,
                    issuerKeyHash, tbsNoSct, certDer);
            System.out.println("        原始类型:  " + (outcome.mode.isEmpty() ? "无法判定" : outcome.mode));
            System.out.println("            状态:  " + outcome.status);
            System.out.println("");
            pos = s + sctLen;
            parsedAny = true;
            no++;
        }
        if (!parsedAny) {
            // 一条都未解析出来（格式异常）：退回打印原始 hex
            System.out.println(hex(value));
        }
    }

    private static String sigName(int hash, int type) {
        // HashAlgorithm 枚举：RFC 5246 §7.4.1.4.1（0=none，1=MD5，2=SHA1，3=SHA224，
        // 4=SHA256，5=SHA384，6=SHA512，7~255 保留；7=SM3 为国密 TLS GB/T 38636-2020
        // 及 RFC 8998 在 TLS 1.3 中的扩展用法）
        String h;
        switch (hash) {
            case 0: h = "none"; break;
            case 1: h = "MD5"; break;
            case 2: h = "SHA1"; break;
            case 3: h = "SHA224"; break;
            case 4: h = "SHA256"; break;
            case 5: h = "SHA384"; break;
            case 6: h = "SHA512"; break;
            case 7: h = "SM3"; break;
            default: h = "HASH" + hash;
        }
        // SignatureAlgorithm 枚举：RFC 5246 §7.4.1.4.1（0=anonymous，1=RSA，2=DSA，
        // 3=ECDSA，4~255 保留）；SM2 在国密生态中有两种实际取值：
        //   4 = 零信国密 CT 日志（sm2ct.cn，参考 RFC 6962 实现，生产证书实测）
        //   7 = 国密 TLS GB/T 38636-2020 / RFC 8998 扩展
        String t;
        switch (type) {
            case 0: t = "anonymous"; break;
            case 1: t = "RSA"; break;
            case 2: t = "DSA"; break;
            case 3: t = "ECDSA"; break;
            case 4: t = "SM2"; break;
            case 7: t = "SM2"; break;
            default: t = "TYPE" + type;
        }
        return t + "-" + h;
    }

    // ============================================================
    // 签名验证 / 证书链
    // ============================================================

    /** 用给定公钥验证证书签名。 */
    private static boolean verifySignature(X509Certificate cert, PublicKey pub) {
        try {
            String sigAlg = cert.getSigAlgName();
            if (sigAlg == null) {
                return false;
            }
            // SM2 签名：用 BC 的 SM2 验签（e = SM3(ZA||TBS)）
            if (sigAlg.toUpperCase().contains("SM2")
                    || cert.getSigAlgOID().equals(Sm2Util.OID_SM3_WITH_SM2)) {
                org.bouncycastle.crypto.params.ECPublicKeyParameters ep =
                        Sm2Util.toEcPublicParams(pub);
                byte[] tbs = cert.getTBSCertificate();
                org.bouncycastle.crypto.signers.SM2Signer signer = new org.bouncycastle.crypto.signers.SM2Signer();
                org.bouncycastle.crypto.params.ParametersWithID pid = new org.bouncycastle.crypto.params.ParametersWithID(
                        ep, Sm2Util.getSm2UidBytes());
                signer.init(false, pid);
                signer.update(tbs, 0, tbs.length);
                byte[] sig = cert.getSignature();
                return signer.verifySignature(sig);
            }
            // RSASSA-PSS（RFC 4055）：从证书签名参数解析哈希，用 *withRSAandMGF1 验签
            if ("1.2.840.113549.1.1.10".equals(cert.getSigAlgOID())) {
                Signature s = Signature.getInstance(pssHashName(cert) + "withRSAandMGF1", "BC");
                s.initVerify(pub);
                s.update(cert.getTBSCertificate());
                return s.verify(cert.getSignature());
            }
            Signature s = Signature.getInstance(sigAlg, "BC");
            s.initVerify(pub);
            s.update(cert.getTBSCertificate());
            return s.verify(cert.getSignature());
        } catch (Exception e) {
            return false;
        }
    }

    /** PKIX 链约束检查（不含有效期——离线/长期验证：证书过期不影响信任关系）。
     *  a) child.issuer DN == parent.subject DN
     *  b) child AKI(若存在) == parent SKI
     *  c) parent KeyUsage(若存在) 必须含 keyCertSign
     *  d) parent 必须是 CA；child 为 CA 时 parent pathLenConstraint 不能为 0
     *  @return {ok, reason} */
    private static String[] chainConstraintsOk(X509Certificate child, X509Certificate parent) {
        if (!child.getIssuerX500Principal().getName()
                .equals(parent.getSubjectX500Principal().getName())) {
            return new String[]{"false", "child.issuer DN != parent.subject DN"};
        }
        byte[] aki = child.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (aki != null) {
            byte[] pSki = parent.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (pSki != null) {
                byte[] akiV = authorityKeyIdValue(aki);
                byte[] pSkiV = subjectKeyIdValue(pSki);
                if (!java.util.Arrays.equals(akiV, pSkiV)) {
                    return new String[]{"false", "child AKI != parent SKI"};
                }
            }
        }
        if (parent.getBasicConstraints() < 0) {
            return new String[]{"false", "parent is not a CA (BasicConstraints CA=false)"};
        }
        boolean[] ku = parent.getKeyUsage();
        if (ku != null && (ku.length <= 5 || !ku[5])) {
            return new String[]{"false", "parent KeyUsage lacks keyCertSign"};
        }
        boolean childIsCa = child.getBasicConstraints() >= 0;
        if (childIsCa && parent.getBasicConstraints() == 0) {
            return new String[]{"false", "因为证书路径中有一个证书颁发机构似乎没有颁发证书的权限或不允许用作终端实体证书,所以此证书无效"};
        }
        return new String[]{"true", ""};
    }

    /** child AKI 是否与 parent SKI 匹配（两者都存在时）。 */
    private static boolean akiMatches(X509Certificate child, X509Certificate parent) {
        byte[] aki = child.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        byte[] pSki = parent.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (aki == null || pSki == null) {
            return false;
        }
        return java.util.Arrays.equals(authorityKeyIdValue(aki), subjectKeyIdValue(pSki));
    }

    /** 静默拉取颁发者证书（不打印证书链/信任状态），供 SCT 验签等内部使用。
     *  优先 AIA caIssuers，AIA 缺失/失败时回退本地 PKI/ROOT、PKI/CA、PKI/MY、java cacerts。 */
    private static X509Certificate fetchIssuerSilent(X509Certificate cert) {
        try {
            List<String> urls = aiaCaIssuers(cert);
            if (!urls.isEmpty()) {
                byte[] data = httpGet(urls.get(0), 10000);
                if (data != null) {
                    return parseCert(data);
                }
            }
        } catch (Exception e) {
        }
        return findLocalIssuer(cert);
    }

    /** 获取颁发者证书：优先 AIA caIssuers URL；AIA 缺失/下载失败时回退本地
     *  PKI/ROOT、PKI/CA、PKI/MY、java cacerts（按 Subject DN + 验签匹配）。
     *  返回直接颁发者用于验签，并打印证书链。 */
    private static X509Certificate fetchIssuer(X509Certificate cert) {
        X509Certificate issuer = null;
        boolean fromLocal = false;
        try {
            List<String> urls = aiaCaIssuers(cert);
            if (!urls.isEmpty()) {
                byte[] data = httpGet(urls.get(0), 10000);
                if (data != null) {
                    X509Certificate cand = parseCert(data);
                    if ("true".equals(chainConstraintsOk(cert, cand)[0])) {
                        issuer = cand;
                    }
                }
            }
        } catch (Exception e) {
        }
        if (issuer == null) {
            issuer = findLocalIssuer(cert);
            if (issuer == null) {
                System.out.println("验证签名： 无法验证签名 |无法找到上级证书链~ ");
                return null;
            }
            fromLocal = true;
        }
        if (fromLocal) {
            System.out.println("验证签名： 颁发者证书来自本地 PKI 目录/cacerts（AIA 缺失或不可用）");
        }
        // 递归打印证书链（CA → … → Root）与信任状态（对齐 Go 版 GetSubPublicKey）
        printChain(issuer);
        return issuer;
    }

    /** 递归打印证书链：中间证书 CA --> SKI，根证书 Root --> SKI，并输出信任状态。
     *  每级都做 child.verify(parent.publicKey) 逐级验签，且上级必须为 CA
     *  （BasicConstraints >= 0）；上级优先 AIA，AIA 缺失/失败时回退本地
     *  PKI/ROOT、PKI/CA、PKI/MY、java cacerts（PKI-004/PKI-005）。 */
    private static void printChain(X509Certificate issuer) {
        String ski = subjectKeyIdHex(issuer);
        if (isSelfSigned(issuer)) {
            System.out.println("       Root --> " + ski);
            if (isInTrustAnchor(issuer)) {
                System.out.println("信任状态： 可信 (此证书已通过信任锚[Root根证书]的验证)\n");
            } else {
                System.out.println("信任状态： 不可信 (根证书不在实验信任锚 PKI/ROOT 中)\n");
            }
            return;
        }
        System.out.println("       CA   --> " + ski);
        X509Certificate parent = null;
        try {
            List<String> urls = aiaCaIssuers(issuer);
            if (!urls.isEmpty()) {
                byte[] data = httpGet(urls.get(0), 10000);
                if (data != null) {
                    parent = parseCert(data);
                }
            }
        } catch (Exception ignore) {
        }
        if (parent == null) {
            parent = findLocalIssuer(issuer);
            if (parent != null) {
                System.out.println("       (上级证书来自本地 PKI/ROOT|PKI/CA|PKI/MY|cacerts)");
            }
        }
        if (parent == null) {
            System.out.println("       CA   -->????????????????????");
            System.out.println("信任状态： 不可信 (由于无法找到上级证书链 或 证书链验证失败，所以它不受信任。)\n");
            return;
        }
        // 逐级验签 + PKIX 链约束（不含有效期——离线/长期验证）
        if (!verifySignature(issuer, parent.getPublicKey())) {
            System.out.println("信任状态： 不可信 (证书链验证失败：本级签名未通过上级公钥验证。)\n");
            return;
        }
        String[] ck = chainConstraintsOk(issuer, parent);
        if (!"true".equals(ck[0])) {
            System.out.println("信任状态： 不可信 (证书链验证失败：" + ck[1] + "。)\n");
            return;
        }
        printChain(parent);
    }

    /** 本地颁发者查找：按证书 Issuer DN 匹配 PKI/ROOT、PKI/CA、PKI/MY 及 java cacerts，
     *  并用候选公钥验签当前证书；无验签成功者退回第一个 DN 匹配（用于链显示）。 */
    private static X509Certificate findLocalIssuer(X509Certificate cert) {
        String issuerDn = cert.getIssuerX500Principal().getName();
        java.util.List<String> dirs = new java.util.ArrayList<>();
        dirs.add(AppPaths.baseDir() + "/PKI/ROOT");
        dirs.add(AppPaths.baseDir() + "/PKI/CA");
        dirs.add(AppPaths.baseDir() + "/PKI/MY");
        X509Certificate firstDnMatch = null;
        X509Certificate verifyOk = null;
        for (String dir : dirs) {
            java.io.File d = new java.io.File(dir);
            java.io.File[] files = d.listFiles();
            if (files == null) {
                continue;
            }
            for (java.io.File f : files) {
                String n = f.getName().toLowerCase();
                if (!n.endsWith(".crt") && !n.endsWith(".cer")
                        && !n.endsWith(".pem") && !n.endsWith(".der")) {
                    continue;
                }
                try {
                    X509Certificate cand = parseCert(java.nio.file.Files.readAllBytes(f.toPath()));
                    if (!cand.getSubjectX500Principal().getName().equals(issuerDn)) {
                        continue;
                    }
                    if (firstDnMatch == null) {
                        firstDnMatch = cand;
                    }
                    // 上级必须是 CA，且（KeyUsage 存在时）须含 keyCertSign
                    if (cand.getBasicConstraints() < 0) {
                        continue;
                    }
                    boolean[] ku = cand.getKeyUsage();
                    if (ku != null && (ku.length <= 5 || !ku[5])) {
                        continue;
                    }
                    if (!verifySignature(cert, cand.getPublicKey())) {
                        continue;
                    }
                    if (akiMatches(cert, cand)) {
                        return cand;
                    }
                    if (verifyOk == null) {
                        verifyOk = cand;
                    }
                } catch (Exception ignore) {
                }
            }
        }
        X509Certificate cac = findLocalIssuerInCacerts(cert, issuerDn);
        if (cac != null) {
            return cac;
        }
        return verifyOk != null ? verifyOk : firstDnMatch;
    }

    /** 在 JAVA cacerts 中查找能验证当前证书签名的同 DN 证书。 */
    private static X509Certificate findLocalIssuerInCacerts(X509Certificate cert, String issuerDn) {
        try {
            java.io.File cac = new java.io.File(System.getProperty("java.home"), "lib/security/cacerts");
            if (!cac.exists()) {
                return null;
            }
            char[] pw = "changeit".toCharArray();
            for (String ksType : new String[]{"JKS", "PKCS12"}) {
                try {
                    java.security.KeyStore ks = java.security.KeyStore.getInstance(ksType);
                    try (java.io.FileInputStream in = new java.io.FileInputStream(cac)) {
                        ks.load(in, pw);
                    }
                    java.util.Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        java.security.cert.Certificate c = ks.getCertificate(aliases.nextElement());
                        if (!(c instanceof X509Certificate)) {
                            continue;
                        }
                        X509Certificate cand = (X509Certificate) c;
                        if (!cand.getSubjectX500Principal().getName().equals(issuerDn)) {
                            continue;
                        }
                        if (cand.getBasicConstraints() < 0) {
                            continue;
                        }
                        boolean[] ku = cand.getKeyUsage();
                        if (ku != null && (ku.length <= 5 || !ku[5])) {
                            continue;
                        }
                        if (!verifySignature(cert, cand.getPublicKey())) {
                            continue;
                        }
                        if (akiMatches(cert, cand) || cand.getBasicConstraints() >= 0) {
                            return cand;
                        }
                    }
                    break;
                } catch (Exception ignore) {
                }
            }
        } catch (Exception ignore) {
        }
        return null;
    }

    /**
     * 实验 TrustAnchor 检查：证书公钥是否存在于 PKI/ROOT/*.crt（按 SPKI 字节匹配）。
     *
     * <p>自签名验证通过只证明签名有效；是否属于当前环境的信任锚，
     * 以 PKI/ROOT 目录中是否登记该根为准（实验型 PKI 的信任模型）。
     */
    private static boolean isInTrustAnchor(X509Certificate cert) {
        try {
            java.io.File rootDir = new java.io.File(AppPaths.baseDir() + "/PKI/ROOT");
            java.io.File[] files = rootDir.listFiles();
            if (files == null) {
                return false;
            }
            byte[] spki = cert.getPublicKey().getEncoded();
            for (java.io.File f : files) {
                String n = f.getName().toLowerCase();
                if (!n.endsWith(".crt") && !n.endsWith(".cer") && !n.endsWith(".der")) {
                    continue;
                }
                try {
                    X509Certificate root = parseCert(java.nio.file.Files.readAllBytes(f.toPath()));
                    // Trust anchor identity = SPKI + subject DN（PKI-006：仅比 SPKI 会误认）
                    if (java.util.Arrays.equals(root.getPublicKey().getEncoded(), spki)
                            && root.getSubjectX500Principal().getName()
                                .equals(cert.getSubjectX500Principal().getName())) {
                        return true;
                    }
                } catch (Exception ignore) {
                }
            }
        } catch (Exception ignore) {
        }
        // 信任锚第二来源：JAVA 环境 lib/security/cacerts 中的证书
        return inJavaCacerts(cert);
    }

    /**
     * JAVA cacerts 信任锚检查：证书公钥（SPKI）是否存在于
     * {@code <java.home>/lib/security/cacerts}（JKS/PKCS12，默认密码 changeit）。
     */
    private static boolean inJavaCacerts(X509Certificate cert) {
        try {
            java.io.File cac = new java.io.File(System.getProperty("java.home"), "lib/security/cacerts");
            if (!cac.exists()) {
                return false;
            }
            byte[] spki = cert.getPublicKey().getEncoded();
            char[] pw = "changeit".toCharArray();
            for (String ksType : new String[]{"JKS", "PKCS12"}) {
                try {
                    java.security.KeyStore ks = java.security.KeyStore.getInstance(ksType);
                    try (java.io.FileInputStream in = new java.io.FileInputStream(cac)) {
                        ks.load(in, pw);
                    }
                    java.util.Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        java.security.cert.Certificate c = ks.getCertificate(aliases.nextElement());
                        if (c instanceof X509Certificate
                                && java.util.Arrays.equals(c.getPublicKey().getEncoded(), spki)
                                && ((X509Certificate) c).getSubjectX500Principal().getName()
                                    .equals(cert.getSubjectX500Principal().getName())) {
                            return true;
                        }
                    }
                    break;
                } catch (Exception ignore) {
                    // 尝试下一种 keystore 类型
                }
            }
        } catch (Exception ignore) {
        }
        return false;
    }

    /** 判断证书是否为自签名（Subject == Issuer）。 */
    private static boolean isSelfSigned(X509Certificate c) {
        return c.getSubjectX500Principal().getName()
                .equals(c.getIssuerX500Principal().getName());
    }

    /** 证书 SKI 纯净 hex（剥离双层 OCTET STRING 包装）。 */
    private static String subjectKeyIdHex(X509Certificate c) {
        try {
            byte[] v = c.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            return v == null ? "" : hex(subjectKeyIdValue(v));
        } catch (Exception e) {
            return "";
        }
    }

    private static List<String> aiaCaIssuers(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(aia)));
        for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(
                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers)) {
                out.add(ad.getAccessLocation().getName().toString());
            }
        }
        return out;
    }

    // ============================================================
    // 吊销状态检查
    // ============================================================

    private static void checkCrl(X509Certificate cert) {
        try {
            List<String> urls = crlUrls(cert);
            if (urls.isEmpty()) {
                System.out.println("CRL无法检查吊销状态 | None~ ");
                return;
            }
            byte[] data = httpGet(urls.get(0), 10000);
            if (data == null) {
                System.out.println("CRL无法检查吊销状态 | 下载失败~ ");
                return;
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
            // ---- CRL 本身验证：颁发者身份 / 签名 / 有效期（P1-03） ----
            X509Certificate issuerCert = fetchIssuerSilent(cert);
            if (issuerCert == null) {
                System.out.println("CRL无法检查吊销状态 | 无法获取颁发者证书验证 CRL~ ");
                return;
            }
            if (!crl.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                System.out.println("CRL无法检查吊销状态 | CRL 颁发者与证书颁发者不匹配~ ");
                return;
            }
            try {
                crl.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                System.out.println("CRL无法检查吊销状态 | CRL 签名验证失败~ ");
                return;
            }
            Date now = new Date();
            if (now.before(crl.getThisUpdate())) {
                System.out.println("CRL无法检查吊销状态 | CRL 尚未生效 (thisUpdate="
                        + crl.getThisUpdate() + ")~ ");
                return;
            }
            if (crl.getNextUpdate() != null && now.after(crl.getNextUpdate())) {
                System.out.println("CRL无法检查吊销状态 | CRL 已过期 (nextUpdate="
                        + crl.getNextUpdate() + ")~ ");
                return;
            }
            X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
            if (entry != null) {
                System.out.println("          此证书已被颁发机构吊销。（CRL） 吊销时间："
                        + entry.getRevocationDate());
            } else {
                System.out.println("证书正常。（CRL）");
            }
        } catch (Exception e) {
            System.out.println("CRL无法检查吊销状态 | 解析失败~ ");
        }
    }

    private static void checkOcsp(X509Certificate cert) {
        try {
            List<String> urls = ocspUrls(cert);
            if (urls.isEmpty()) {
                System.out.println("        OCSP无法检查吊销状态:None~ ");
                return;
            }
            X509Certificate issuerCert = fetchIssuerSilent(cert);
            if (issuerCert == null) {
                System.out.println("        OCSP无法检查吊销状态 | 无法获取颁发者证书~ ");
                return;
            }
            // 构造 OCSP 请求（CertID 用 SHA1，RFC 5019 兼容；含 Nonce，RFC 6960 §4.4.1）
            byte[][] reqAndNonce = buildOcspRequest(cert, issuerCert);
            byte[] req = reqAndNonce[0];
            byte[] reqNonce = reqAndNonce[1];
            HttpURLConnection conn = (HttpURLConnection) new java.net.URI(urls.get(0)).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/ocsp-request");
            conn.setRequestProperty("Accept", "application/ocsp-response");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(req);
            }
            byte[] resp = readAll(conn.getInputStream());
            org.bouncycastle.cert.ocsp.OCSPResp ocspResp =
                    new org.bouncycastle.cert.ocsp.OCSPResp(resp);
            // responseStatus：0 = successful
            if (ocspResp.getStatus() != 0) {
                System.out.println("        OCSP响应状态异常: " + ocspResp.getStatus() + "~ ");
                return;
            }
            org.bouncycastle.cert.ocsp.BasicOCSPResp basic =
                    (org.bouncycastle.cert.ocsp.BasicOCSPResp) ocspResp.getResponseObject();
            // 响应签名验证（responder 授权：内嵌 OCSP 证书或签发者直接应答）
            PublicKey respKey;
            try {
                respKey = ocspResponderKey(basic, issuerCert);
            } catch (Exception e) {
                System.out.println("        OCSP响应者授权验证失败: " + e.getMessage() + "~ ");
                return;
            }
            if (!basic.isSignatureValid(
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                            .setProvider("BC").build(respKey))) {
                System.out.println("        OCSP响应签名验证失败~ ");
                return;
            }
            org.bouncycastle.cert.ocsp.SingleResp single =
                    basic.getResponses()[0];
            // CertID 对应性
            org.bouncycastle.cert.ocsp.CertificateID reqCid =
                    new org.bouncycastle.cert.ocsp.CertificateID(
                            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                                    .setProvider("BC").build()
                                    .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                            new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.14.3.2.26"))),
                            new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuerCert),
                            cert.getSerialNumber());
            // 逐字段比对（RFC 6960 CertID 对应性）；不用 CertificateID.equals()，
            // 因为 BC 会对 AlgorithmIdentifier 参数表示（null vs DERNull）敏感，
            // 而响应与服务端 SM2 手动 ASN.1 分支参数表示可能不同（哈希字节实际一致）。
            org.bouncycastle.cert.ocsp.CertificateID respCid = single.getCertID();
            if (!respCid.getHashAlgOID().equals(reqCid.getHashAlgOID())
                    || !java.util.Arrays.equals(respCid.getIssuerNameHash(),
                            reqCid.getIssuerNameHash())
                    || !java.util.Arrays.equals(respCid.getIssuerKeyHash(),
                            reqCid.getIssuerKeyHash())
                    || !respCid.getSerialNumber().equals(reqCid.getSerialNumber())) {
                System.out.println("        OCSP响应 CertID 与请求不匹配~ ");
                return;
            }
            // Nonce 回显（RFC 6960 §4.4.1）：Nonce 位于 BasicOCSPResponse 全局
            // responseExtensions，而非 SingleResp 扩展；存在且值一致才算回显成功
            Extension nonceExt = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExt == null) {
                System.out.println("        OCSP响应缺少 Nonce 回显（可接受，部分实现不回显）~ ");
            } else if (!java.util.Arrays.equals(nonceExt.getExtnValue().getOctets(), reqNonce)) {
                System.out.println("        OCSP响应 Nonce 回显值不一致（可接受，部分实现不回显）~ ");
            }
            // 新鲜度：thisUpdate / nextUpdate
            Date now = new Date();
            if (now.before(single.getThisUpdate())) {
                System.out.println("        OCSP响应尚未生效 (thisUpdate="
                        + single.getThisUpdate() + ")~ ");
                return;
            }
            if (single.getNextUpdate() != null && now.after(single.getNextUpdate())) {
                System.out.println("        OCSP响应已过期 (nextUpdate="
                        + single.getNextUpdate() + ")~ ");
                return;
            }
            Object st = single.getCertStatus();
            if (st == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                System.out.println("          证书正常。（OCSP）");
            } else if (st instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                org.bouncycastle.cert.ocsp.RevokedStatus rs =
                        (org.bouncycastle.cert.ocsp.RevokedStatus) st;
                System.out.println("          此证书已被颁发机构吊销。（OCSP）吊销时间："
                        + rs.getRevocationTime() + " 原因:" + rs.getRevocationReason());
            } else {
                System.out.println("          证书未知。（OCSP）");
            }
        } catch (Exception e) {
            System.out.println("          OCSP无法检查吊销状态 | 上报失败~ ");
        }
    }

    /**
     * 取 OCSP 响应者公钥（responder 授权，RFC 6960 §4.2.2.3）：
     * 优先使用 BasicOCSPResp 内嵌的 OCSP 签名证书；无内嵌证书时
     * 视为颁发者直接应答，使用颁发者公钥。
     */
    private static PublicKey ocspResponderKey(
            org.bouncycastle.cert.ocsp.BasicOCSPResp basic,
            X509Certificate issuerCert) throws Exception {
        org.bouncycastle.cert.X509CertificateHolder[] holders = basic.getCerts();
        if (holders != null && holders.length > 0) {
            X509Certificate respCert = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(holders[0]);
            // Responder authorization (RFC 6960 SS4.2.2.2): 授权链 + id-kp-OCSPSigning EKU。
            // 有效期仅提示、不作为拒绝条件——离线/长期验证，证书过期不影响信任关系。
            java.util.Date now = new java.util.Date();
            if (now.before(respCert.getNotBefore()) || now.after(respCert.getNotAfter())) {
                System.out.println("（提示：OCSP responder 证书已不在有效期窗口内，按离线验证继续）");
            }
            // 授权验证：responder 必须由 issuer CA 签发（或与 issuer 为同一证书）
            if (!respCert.getSubjectX500Principal().getName()
                    .equals(issuerCert.getSubjectX500Principal().getName())) {
                try {
                    respCert.verify(issuerCert.getPublicKey());
                } catch (Exception e) {
                    throw new Exception("OCSP responder certificate not issued by this CA "
                            + "(delegated responder authorization failed)");
                }
            }
            boolean hasOcspEku = false;
            try {
                java.util.List<String> ekus = respCert.getExtendedKeyUsage();
                if (ekus != null) {
                    for (String eku : ekus) {
                        if ("1.3.6.1.5.5.7.3.9".equals(eku)) {
                            hasOcspEku = true;
                            break;
                        }
                    }
                }
            } catch (Exception ignore) {
            }
            if (!hasOcspEku) {
                throw new Exception("OCSP responder certificate lacks id-kp-OCSPSigning EKU (1.3.6.1.5.5.7.3.9)");
            }
            return respCert.getPublicKey();
        }
        // No embedded responder cert: issuer directly signed the response
        return issuerCert.getPublicKey();
    }

    /** 构造 SHA1 CertID 的 OCSP 请求（含 Nonce 扩展）。返回 {请求字节, nonce}。 */
    private static byte[][] buildOcspRequest(X509Certificate cert,
                                             X509Certificate issuerCert) throws Exception {
        org.bouncycastle.cert.ocsp.CertificateID cid =
                new org.bouncycastle.cert.ocsp.CertificateID(
                        new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                                .setProvider("BC").build()
                                .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.14.3.2.26"))),
                        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuerCert),
                        cert.getSerialNumber());
        org.bouncycastle.cert.ocsp.OCSPReqBuilder builder =
                new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
        builder.addRequest(cid);
        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);
        builder.setRequestExtensions(new org.bouncycastle.asn1.x509.Extensions(
                new org.bouncycastle.asn1.x509.Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                        false, new DEROctetString(nonce))));
        return new byte[][]{builder.build().getEncoded(), nonce};
    }

    private static List<String> crlUrls(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.CRLDistPoint cdp =
                org.bouncycastle.asn1.x509.CRLDistPoint.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(ext)));
        for (org.bouncycastle.asn1.x509.DistributionPoint dp : cdp.getDistributionPoints()) {
            if (dp.getDistributionPoint() != null
                    && dp.getDistributionPoint().getName() != null) {
                org.bouncycastle.asn1.x509.GeneralNames gns =
                        org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                                dp.getDistributionPoint().getName());
                for (org.bouncycastle.asn1.x509.GeneralName gn : gns.getNames()) {
                    out.add(gn.getName().toString());
                }
            }
        }
        return out;
    }

    private static List<String> ocspUrls(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(aia)));
        for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(
                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp)) {
                out.add(ad.getAccessLocation().getName().toString());
            }
        }
        return out;
    }

    // ============================================================
    // 哈希打印
    // ============================================================

    private static void printHashes(X509Certificate cert, PublicKey pub) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        byte[] spki = pub.getEncoded();
        byte[] spkiSha1 = sha1.digest(spki);
        byte[] spkiSha256 = sha256.digest(spki);
        System.out.println("");
        System.out.println("密钥 Id 哈希(SHA1)          ： " + hex(spkiSha1));
        System.out.println("密钥 Id 哈希(RFC-SHA1)      ： " + hex(rfcSha1(pub)));
        System.out.println("密钥 Id 哈希(Pin-SHA256)    ： "
                + Base64.getEncoder().encodeToString(spkiSha256));
        System.out.println("密钥 Id 哈希(Pin-SHA256-Hex)： " + hex(spkiSha256));
        System.out.println("\n");

        byte[] raw = cert.getEncoded();
        System.out.println("证书哈希(SHA1)              ： " + hex(sha1.digest(raw)));
        System.out.println("证书哈希(SHA256)            ： " + hex(sha256.digest(raw)));
        System.out.println("签名哈希                    ： " + hex(sha256.digest(cert.getTBSCertificate())));
    }

    /** RFC5280 方法1 的密钥标识（RSA：PKCS#1 位串；ECC/SM2：未压缩点）。 */
    private static byte[] rfcSha1(PublicKey pub) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        if (pub instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsa =
                    (java.security.interfaces.RSAPublicKey) pub;
            org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1 =
                    new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsa.getModulus(), rsa.getPublicExponent());
            return md.digest(pkcs1.getEncoded());
        }
        if (pub instanceof java.security.interfaces.ECPublicKey) {
            java.security.interfaces.ECPublicKey ec =
                    (java.security.interfaces.ECPublicKey) pub;
            // 未压缩点：04 || X || Y（固定长度，X/Y 按曲线字节数填充）
            int size = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            byte[] x = ec.getW().getAffineX().toByteArray();
            byte[] y = ec.getW().getAffineY().toByteArray();
            byte[] xy = new byte[1 + 2 * size];
            xy[0] = 0x04;
            copyRightAligned(x, xy, 1, size);
            copyRightAligned(y, xy, 1 + size, size);
            return md.digest(xy);
        }
        return md.digest(pub.getEncoded());
    }

    private static void copyRightAligned(byte[] src, byte[] dst, int offset, int size) {
        int srcLen = src.length;
        int shift = 0;
        if (srcLen > size) {
            // 去掉可能的前导 00
            int s = 0;
            while (s < srcLen - 1 && src[s] == 0) {
                s++;
            }
            System.arraycopy(src, s, dst, offset, srcLen - s);
        } else {
            System.arraycopy(src, 0, dst, offset + size - srcLen, srcLen);
        }
    }

    // ============================================================
    // HTTP / 工具
    // ============================================================

    /** HTTP 响应最大字节数（防恶意证书 AIA/CRL/OCSP 拉取超大响应，P2-01）。 */
    private static final int MAX_HTTP_SIZE = 5 * 1024 * 1024;

    private static byte[] httpGet(String url, int timeoutMs) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
            // 网络策略（P2-02）：只允许 HTTP / HTTPS，拒绝 file: 等其它协议
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return null;
            }
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            int code = conn.getResponseCode();
            if (code != 200) {
                return null;
            }
            return readAll(conn.getInputStream());
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            if (out.size() > MAX_HTTP_SIZE) {
                throw new IOException("HTTP 响应超过大小限制 "
                        + (MAX_HTTP_SIZE / 1024 / 1024) + "MB");
            }
        }
        return out.toByteArray();
    }

    /** 去掉扩展值的 OCTET STRING 外层。 */
    private static byte[] unwrapOctets(byte[] extValue) {
        try {
            ASN1OctetString os = ASN1OctetString.getInstance(
                    ASN1Primitive.fromByteArray(extValue));
            return os.getOctets();
        } catch (Exception e) {
            return extValue;
        }
    }

    /** SKI 扩展值 → 纯净字节：extValue(04..) → SubjectKeyIdentifier(04 14 ..) → 20 字节。 */
    private static byte[] subjectKeyIdValue(byte[] extValue) {
        try {
            return unwrapOctets(unwrapOctets(extValue));
        } catch (Exception e) {
            return unwrapOctets(extValue);
        }
    }

    /** AKI 扩展值 → keyIdentifier 纯净字节：用 BC 解析 AuthorityKeyIdentifier 结构。 */
    private static byte[] authorityKeyIdValue(byte[] extValue) {
        try {
            org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki =
                    org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(extValue)));
            byte[] kid = aki.getKeyIdentifierOctets();
            return kid != null ? kid : new byte[0];
        } catch (Exception e) {
            return unwrapOctets(extValue);
        }
    }

    private static byte[][] chunks(byte[] data) {
        java.util.List<byte[]> list = new java.util.ArrayList<>();
        int start = 0;
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == 0 && data[i + 1] == 0) {
                list.add(java.util.Arrays.copyOfRange(data, start, i));
                start = i + 2;
                i++;
            }
        }
        list.add(java.util.Arrays.copyOfRange(data, start, data.length));
        return list.toArray(new byte[0][]);
    }

    private static int indexOf(byte[] data, byte[] needle) {
        for (int i = 0; i <= data.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String bitsToString(boolean[] bits) {
        if (bits == null) {
            return "无";
        }
        StringBuilder sb = new StringBuilder();
        String[] names = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                "encipherOnly", "decipherOnly"};
        for (int i = 0; i < bits.length && i < names.length; i++) {
            if (bits[i]) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(names[i]);
            }
        }
        return sb.toString();
    }


    // ============================================================
    // SCT 列表签名验证（RFC 6962 / Certificate Transparency）
    // ============================================================

    /** 单条 SCT 结构化数据（RFC 6962 SerializedSCT）。 */
    private static final class SctInfo {
        int version;
        byte[] logId;
        long timestamp;
        byte[] extensions;
        int hashAlg;
        int sigAlg;
        byte[] signature;
    }

    /** SCT 扩展 OID（RFC 6962 3.2）。 */
    private static final String SCT_EXT_OID = "1.3.6.1.4.1.11129.2.4.2";

    /** 解析 TLS 编码的 SCT 列表。SCTList = uint16 totalLen + [uint16 sctLen + SerializedSCT]*。 */
    private static List<SctInfo> parseSctListData(byte[] value) {
        List<SctInfo> out = new ArrayList<>();
        byte[] tls = value;
        for (int i = 0; i < 2 && tls != null && tls.length > 0 && (tls[0] & 0xff) == 0x04; i++) {
            byte[] inner = unwrapOctets(tls);
            if (inner == tls) {
                break;
            }
            tls = inner;
        }
        if (tls == null || tls.length < 2) {
            return out;
        }
        int totalLen = ((tls[0] & 0xff) << 8) | (tls[1] & 0xff);
        int pos = 2;
        int end = Math.min(pos + totalLen, tls.length);
        while (pos + 2 <= end) {
            int sctLen = ((tls[pos] & 0xff) << 8) | (tls[pos + 1] & 0xff);
            pos += 2;
            if (sctLen < 47 || pos + sctLen > end) {
                break;
            }
            int s = pos;
            SctInfo info = new SctInfo();
            info.version = tls[s] & 0xff;
            info.logId = java.util.Arrays.copyOfRange(tls, s + 1, s + 33);
            long timestamp = 0;
            for (int i = 0; i < 8; i++) {
                timestamp = (timestamp << 8) | (tls[s + 33 + i] & 0xff);
            }
            info.timestamp = timestamp;
            int p = s + 41;
            int extLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            info.extensions = extLen > 0
                    ? java.util.Arrays.copyOfRange(tls, p, p + extLen) : new byte[0];
            p += extLen;
            if (p + 4 > s + sctLen) {
                break;
            }
            info.hashAlg = tls[p++] & 0xff;
            info.sigAlg = tls[p++] & 0xff;
            int sigLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            if (p + sigLen > s + sctLen) {
                break;
            }
            info.signature = java.util.Arrays.copyOfRange(tls, p, p + sigLen);
            out.add(info);
            pos = s + sctLen;
        }
        return out;
    }

    /**
     * 计算单条 SCT 的验证状态（并入 SCT列表 详细输出）。
     * 状态三态：签名有效 / 签名无效 / 未知日志，无法验证。
     * 原始类型：签名输入按 precert_entry（预证书模式）还是 x509_entry（正式证书模式）验签成功。
     */
    private static SctVerifyOutcome sctStatus(byte[] logId, int version, long timestamp,
                                              byte[] extensions, int hashAlg, int sigAlg,
                                              byte[] signature, Map<String, String[]> logKeys,
                                              X509Certificate issuer, byte[] issuerKeyHash,
                                              byte[] tbsNoSct, byte[] certDer) {
        String b64 = Base64.getEncoder().encodeToString(logId);
        String[] lk = logKeys == null ? null : logKeys.get(b64);
        if (lk == null) {
            return new SctVerifyOutcome("未知日志，无法验证。", "");
        }
        if (issuer == null || issuerKeyHash == null || tbsNoSct == null || certDer == null) {
            return new SctVerifyOutcome("未知日志，无法验证。", "");
        }
        try {
            byte[] spki = Base64.getDecoder().decode(lk[1]);
            SctInfo sct = new SctInfo();
            sct.version = version;
            sct.logId = logId;
            sct.timestamp = timestamp;
            sct.extensions = extensions;
            sct.hashAlg = hashAlg;
            sct.sigAlg = sigAlg;
            sct.signature = signature;
            // 先按预证书模式（precert_entry，issuer_key_hash + PreCert TBS）验签；
            // 失败再按正式证书模式（x509_entry，剥离 SCT 扩展的 TBSCertificate）验签。
            boolean okPre = verifySctSignature(
                    buildSctInput(sct, issuerKeyHash, tbsNoSct, certDer, true), sct, spki);
            if (okPre) {
                return new SctVerifyOutcome("签名有效", "预证书模式(precert_entry)");
            }
            boolean okX = verifySctSignature(
                    buildSctInput(sct, issuerKeyHash, tbsNoSct, certDer, false), sct, spki);
            if (okX) {
                return new SctVerifyOutcome("签名有效", "正式证书模式(x509_entry)");
            }
            return new SctVerifyOutcome("签名无效", "");
        } catch (Exception e) {
            return new SctVerifyOutcome("签名无效", "");
        }
    }

    /** SCT 验证结果：状态 + 原始类型标注。 */
    private static final class SctVerifyOutcome {
        final String status;
        final String mode;

        SctVerifyOutcome(String status, String mode) {
            this.status = status;
            this.mode = mode;
        }
    }

    /** 构造 RFC 6962 3.2 的签名输入（precert=true 用 PreCert，否则用完整证书）。 */
    private static byte[] buildSctInput(SctInfo sct, byte[] issuerKeyHash,
                                        byte[] tbsNoSct, byte[] certDer, boolean precert)
            throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(sct.version);                    // version（v1 = 0）
        bos.write(0);                               // signature_type = certificate_timestamp
        writeU64(bos, sct.timestamp);
        if (precert) {
            writeU16(bos, 1);                       // entry_type = precert_entry
            bos.write(issuerKeyHash);               // issuer_key_hash（32 字节）
            writeU24(bos, tbsNoSct.length);
            bos.write(tbsNoSct);
        } else {
            // RFC 6962 §3.2：x509_entry 的 signed_entry = 叶子证书 TBSCertificate（剥离 SCT 扩展后的 TBS）
            writeU16(bos, 0);                       // entry_type = x509_entry
            writeU24(bos, tbsNoSct.length);
            bos.write(tbsNoSct);
        }
        writeU16(bos, sct.extensions.length);
        bos.write(sct.extensions);
        return bos.toByteArray();
    }

    /** 从证书 TBS 中移除 SCT 扩展（RFC 6962 3.1 PreCert.tbs_certificate）。 */
    private static byte[] tbsWithoutSctExt(X509Certificate cert) throws Exception {
        byte[] tbs = cert.getTBSCertificate();
        ASN1Sequence seq = ASN1Sequence.getInstance(tbs);
        ASN1EncodableVector v = new ASN1EncodableVector();
        boolean removed = false;
        for (int i = 0; i < seq.size(); i++) {
            ASN1Encodable el = seq.getObjectAt(i);
            if (el instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) el;
                if (tagged.getTagNo() == 3) {
                    ASN1Sequence extSeq = ASN1Sequence.getInstance(tagged, true);
                    ASN1EncodableVector newExts = new ASN1EncodableVector();
                    for (int j = 0; j < extSeq.size(); j++) {
                        Extension ext = Extension.getInstance(extSeq.getObjectAt(j));
                        if (!SCT_EXT_OID.equals(ext.getExtnId().getId())) {
                            newExts.add(ext);
                        } else {
                            removed = true;
                        }
                    }
                    // RFC 6962 3.1：tbs_certificate = 最终证书 TBS 删除 SCT 扩展（不含 poison）
                    v.add(new DERTaggedObject(true, 3, new DERSequence(newExts)));
                    continue;
                }
            }
            v.add(el);
        }
        return removed ? new DERSequence(v).getEncoded() : tbs;
    }

    /** 用日志公钥（SPKI DER）验证 SCT 签名。hash/sig 为 TLS 算法枚举（RFC 5246 / RFC 8422）。 */
    private static boolean verifySctSignature(byte[] input, SctInfo sct, byte[] spkiDer)
            throws Exception {
        int hash = sct.hashAlg;
        int sig = sct.sigAlg;
        if (sig == 3) { // ECDSA：实际日志多为 DER 签名（RFC 6962 亦允许 TLS 裸 r||s，兼容处理）
            Signature s = Signature.getInstance("SHA" + tlsHashName(hash) + "withECDSA", "BC");
            KeyFactory kf = KeyFactory.getInstance("EC");
            s.initVerify(kf.generatePublic(new X509EncodedKeySpec(spkiDer)));
            s.update(input);
            if (s.verify(sct.signature)) {
                return true; // DER 格式
            }
            try {
                return s.verify(ecdsaRawToDer(sct.signature)); // TLS 裸 r||s 兼容
            } catch (Exception ignore) {
                return false;
            }
        }
        if (sig == 1) { // RSA（RSASSA-PKCS1-v1_5）
            Signature s = Signature.getInstance("SHA" + tlsHashName(hash) + "withRSA", "BC");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            s.initVerify(kf.generatePublic(new X509EncodedKeySpec(spkiDer)));
            s.update(input);
            return s.verify(sct.signature);
        }
        if ((sig == 4 || sig == 7) && hash == 7) {
            // SM2 / SM3：sig=7 为国密 TLS GB/T 38636-2020 / RFC 8998 枚举；
            // sig=4 为零信国密 CT 日志（sm2ct.cn）实现枚举（生产证书实测，如 ZoTrus SM2 SSL Pro）
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spkiDer));
            return Sm2Util.sm2Verify(Sm2Util.toEcPublicParams(pub), input, sct.signature);
        }
        return false;
    }

    /** TLS HashAlgorithm 枚举 → JCA 哈希数字后缀。 */
    private static String tlsHashName(int hash) {
        switch (hash) {
            case 2:
                return "1";     // SHA-1
            case 4:
                return "256";
            case 5:
                return "384";
            case 6:
                return "512";
            default:
                return "256";
        }
    }

    /** TLS ECDSA 定长 r||s → DER SEQUENCE { INTEGER r, INTEGER s }。 */
    private static byte[] ecdsaRawToDer(byte[] raw) throws Exception {
        int half = raw.length / 2;
        byte[] r = new byte[half];
        byte[] s = new byte[half];
        System.arraycopy(raw, 0, r, 0, half);
        System.arraycopy(raw, half, s, 0, half);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(new BigInteger(1, r)));
        v.add(new ASN1Integer(new BigInteger(1, s)));
        return new DERSequence(v).getEncoded();
    }

    /**
     * Load CT log public keys: Google log_list v3 + local PKI/CTLOG/modpkica_ct_list.json (merged).
     * Returns log_id(base64) -> [description, key(base64 SPKI)].
     */

    private static Map<String, String[]> loadCtLogKeys() {
        String base = AppPaths.baseDir();
        String[] candidates = {
                base + "/log_list.json",
                base + "/PKI/log_list.json",
                base + "/PKI/WebPublic/log_list.json",
                base + "/PKI/CTLOG/modpkica_ct_list.json"
        };
        Map<String, String[]> map = new HashMap<>();
        Pattern pid = Pattern.compile("\"log_id\"\\s*:\\s*\"([^\"]+)\"");
        Pattern pdesc = Pattern.compile("\"description\"\\s*:\\s*\"([^\"]+)\"");
        Pattern pkey = Pattern.compile("\"key\"\\s*:\\s*\"([^\"]+)\"");
        for (String c : candidates) {
            Path p = Paths.get(c);
            if (!Files.exists(p)) {
                continue;
            }
            String json;
            try {
                json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            } catch (IOException ignore) {
                continue;
            }
            Matcher m = pid.matcher(json);
            while (m.find()) {
                int objStart = json.lastIndexOf("{", m.start());
                int objEnd = json.indexOf("}", m.end());
                if (objStart < 0) {
                    objStart = 0;
                }
                if (objEnd < 0) {
                    objEnd = json.length();
                }
                if (objEnd < objStart) {
                    objEnd = json.length();
                }
                String seg = json.substring(objStart, objEnd);
                Matcher km = pkey.matcher(seg);
                if (!km.find()) {
                    continue;
                }
                String desc = "";
                Matcher dm = pdesc.matcher(seg);
                if (dm.find()) {
                    desc = dm.group(1);
                }
                map.put(m.group(1), new String[]{desc, km.group(1)});
            }
        }
        return map.isEmpty() ? null : map;
    }
    private static void writeU16(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    private static void writeU24(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 16) & 0xff);
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    private static void writeU64(ByteArrayOutputStream bos, long v) {
        for (int i = 7; i >= 0; i--) {
            bos.write((int) ((v >>> (8 * i)) & 0xff));
        }
    }



    /** 从 RSASSA-PSS 证书签名参数解析哈希名（大写，SHA3 带连字符，供 JCA 算法名使用）。 */
    private static String pssHashName(X509Certificate cert) {
        try {
            byte[] params = cert.getSigAlgParams();
            if (params != null) {
                org.bouncycastle.asn1.pkcs.RSASSAPSSparams pss =
                        org.bouncycastle.asn1.pkcs.RSASSAPSSparams.getInstance(params);
                String h = pss.getHashAlgorithm().getAlgorithm().getId();
                switch (h) {
                    case "1.3.14.3.2.26": return "SHA1";
                    case "2.16.840.1.101.3.4.2.4": return "SHA224";
                    case "2.16.840.1.101.3.4.2.1": return "SHA256";
                    case "2.16.840.1.101.3.4.2.2": return "SHA384";
                    case "2.16.840.1.101.3.4.2.3": return "SHA512";
                    case "2.16.840.1.101.3.4.2.7": return "SHA3-224";
                    case "2.16.840.1.101.3.4.2.8": return "SHA3-256";
                    case "2.16.840.1.101.3.4.2.9": return "SHA3-384";
                    case "2.16.840.1.101.3.4.2.10": return "SHA3-512";
                    default: return "SHA256";
                }
            }
        } catch (Exception ignore) { /* 参数缺失/解析失败回退 SHA256 */ }
        return "SHA256";
    }

}