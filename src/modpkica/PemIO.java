package modpkica;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * PemIO —— PEM 文件读写工具。
 *
 * <p>文件命名约定：证书为 {@code 序列号.crt}，私钥为 {@code 序列号.key}。
 * <p>PEM 头部 Type 约定：
 * <ul>
 *   <li>证书：{@code CERTIFICATE}</li>
 *   <li>RSA 私钥：{@code RSA PRIVATE KEY}（PKCS#1）</li>
 *   <li>ECC 私钥：{@code EC PRIVATE KEY}（SEC1）</li>
 *   <li>SM2 私钥：{@code SM2 PRIVATE KEY}（PKCS#8，国密自定义头）</li>
 * </ul>
 *
 * <p>SM2 使用自定义头 {@code SM2 PRIVATE KEY}，BC 的 PEMParser 不认识该类型，
 * 因此本类按“先读头部识别类型 → 再按对应 ASN.1 结构解析 DER”的方式手动处理。
 */
public final class PemIO {

    /** 注册 BC Provider（读证书/密钥几乎总是第一步操作） */
    static {
        Bc.init();
    }

    private PemIO() {
    }

    // ============================ 读证书 ============================

    /**
     * 读取 PEM 证书文件为 X509Certificate。
     *
     * @param path crt 文件路径
     * @return X509Certificate
     */
    public static X509Certificate readCert(String path) throws Exception {
        PemObject po = readPemObject(path);
        if (po == null) {
            throw new IllegalArgumentException("PEM 内容为空: " + path);
        }
        X509CertificateHolder holder = new X509CertificateHolder(po.getContent());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // ============================ 读私钥 ============================

    /**
     * 读取私钥 PEM，自动识别 RSA / ECC / SM2，返回 BC 的 AsymmetricKeyParameter。
     *
     * <p>注意：BC 的 PEMParser 不识别国密自定义头 SM2 PRIVATE KEY（会直接抛
     * "unrecognised object"），因此这里手动解析 PEM 块：
     * <ul>
     *   <li>SM2 PRIVATE KEY / PRIVATE KEY → 内容即 PKCS#8 PrivateKeyInfo</li>
     *   <li>RSA PRIVATE KEY → PKCS#1 RSAPrivateKey，包装为 PrivateKeyInfo</li>
     *   <li>EC PRIVATE KEY → SEC1 ECPrivateKey，包装为 PrivateKeyInfo</li>
     * </ul>
     */
    public static AsymmetricKeyParameter readPrivateKey(String path) throws Exception {
        String text = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);

        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "-----BEGIN ([A-Z0-9 ]+)-----\\s*([A-Za-z0-9+/=\\r\\n]+?)-----END",
                java.util.regex.Pattern.DOTALL);
        java.util.regex.Matcher m = p.matcher(text);
        if (!m.find()) {
            throw new IllegalArgumentException("未找到 PEM 私钥块: " + path);
        }
        String type = m.group(1).trim();
        String b64 = m.group(2).replaceAll("\\s", "");
        byte[] der = java.util.Base64.getDecoder().decode(b64);

        switch (type) {
            case "SM2 PRIVATE KEY":
            case "PRIVATE KEY": {
                // PKCS#8 直通
                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(der);
                return PrivateKeyFactory.createKey(pki);
            }
            case "ENCRYPTED PRIVATE KEY": {
                // 加密私钥（EncryptedPrivateKeyInfo）需密码解密，本项目离线环境不存储口令，
                // 明确报错而非解析失败（旧实现会把加密块当 PKCS#8 解析，报错难以理解）
                throw new IllegalArgumentException(
                        "不支持加密私钥（ENCRYPTED PRIVATE KEY）：请先解密为标准 PKCS#8 私钥再导入");
            }
            case "RSA PRIVATE KEY": {
                // PKCS#1 -> PrivateKeyInfo
                RSAPrivateKey rsa = RSAPrivateKey.getInstance(der);
                AlgorithmIdentifier alg = new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                return PrivateKeyFactory.createKey(new PrivateKeyInfo(alg, rsa));
            }
            case "EC PRIVATE KEY": {
                // SEC1 -> PrivateKeyInfo（带曲线参数）
                ECPrivateKey ec = ECPrivateKey.getInstance(der);
                AlgorithmIdentifier alg = new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_ecPublicKey, ec.getParametersObject());
                return PrivateKeyFactory.createKey(new PrivateKeyInfo(alg, ec));
            }
            default:
                throw new IllegalArgumentException("不支持的私钥类型: " + type);
        }
    }

    // ============================ 写证书 ============================

    /**
     * 把 X509Certificate 写成 PEM（Type=CERTIFICATE）。
     *
     * @param path 输出 crt 文件路径
     * @param cert 证书
     */
    public static void writeCert(String path, X509Certificate cert) throws Exception {
        PemObject po = new PemObject("CERTIFICATE", cert.getEncoded());
        writePemObject(path, po);
    }

    // ============================ 写私钥 ============================

    /**
     * 写私钥 PEM。
     *
     * @param path    输出 key 文件路径
     * @param key     私钥（可为 AsymmetricKeyParameter 或 JCA PrivateKey）
     * @param keyType "RSA" / "ECC" / "SM2"
     */
    public static void writePrivateKey(String path, Object key, String keyType) throws Exception {
        // 统一为 PKCS#8 的 PrivateKeyInfo
        PrivateKeyInfo pki;
        if (key instanceof AsymmetricKeyParameter) {
            pki = PrivateKeyInfoFactory.createPrivateKeyInfo((AsymmetricKeyParameter) key);
        } else if (key instanceof PrivateKey) {
            // JCA 私钥 getEncoded() 即 PKCS#8
            pki = PrivateKeyInfo.getInstance(((PrivateKey) key).getEncoded());
        } else {
            throw new IllegalArgumentException("不支持的 key 类型: " + key.getClass().getName());
        }

        String type;
        byte[] der;
        if ("RSA".equalsIgnoreCase(keyType) || "RSA-PSS".equalsIgnoreCase(keyType)) {
            // 转 PKCS#1
            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pki.parsePrivateKey());
            type = "RSA PRIVATE KEY";
            der = rsa.getEncoded();
        } else if ("ECC".equalsIgnoreCase(keyType)) {
            // 转 SEC1 ECPrivateKey：parsePrivateKey() 返回的是 ECPrivateKey 的 ASN1 SEQUENCE
            // （不能用 (ASN1OctetString) 强转，SEC1 结构是 SEQUENCE{version, privateKey, ...}）
            ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(
                    pki.getPrivateKeyAlgorithm().getParameters());
            ECPrivateKey sec1 = ECPrivateKey.getInstance(pki.parsePrivateKey());
            java.math.BigInteger d = sec1.getKey();
            int bitLen = lookupCurveBitLength(curveOid);
            ECPrivateKey ec = new ECPrivateKey(bitLen, d, curveOid);
            type = "EC PRIVATE KEY";
            der = ec.getEncoded();
        } else if ("SM2".equalsIgnoreCase(keyType)) {
            // 直接写 PKCS#8，但用国密自定义头
            type = "SM2 PRIVATE KEY";
            der = pki.getEncoded();
        } else if ("PQC".equalsIgnoreCase(keyType) || "DSA".equalsIgnoreCase(keyType)
                || "EdDSA".equalsIgnoreCase(keyType)) {
            // PQC（ML-DSA/SLH-DSA/ML-KEM 等）、DSA、EdDSA（Ed25519/Ed448）：
            // 统一写标准 PKCS#8 PRIVATE KEY（BC 读回时按算法 OID 判别类型）
            type = "PRIVATE KEY";
            der = pki.getEncoded();
        } else {
            throw new IllegalArgumentException("未知 keyType: " + keyType);
        }

        writePemObject(path, new PemObject(type, der));
    }

    /**
     * 根据 PEM 头部 Type 判断密钥类型。
     *
     * @param pemPath PEM 文件路径
     * @return "RSA" / "ECC" / "SM2"；无法识别返回 null
     */
    public static String detectKeyType(String pemPath) throws Exception {
        PemObject po = readPemObject(pemPath);
        if (po == null) {
            return null;
        }
        String t = po.getType();
        if (t.equals("RSA PRIVATE KEY")) {
            return "RSA";
        }
        if (t.equals("EC PRIVATE KEY")) {
            return "ECC";
        }
        if (t.equals("SM2 PRIVATE KEY") || t.equals("PRIVATE KEY")) {
            // 需进一步判断曲线是否为 SM2；SM2 文件头已明确写 SM2 PRIVATE KEY
            if (t.equals("SM2 PRIVATE KEY")) {
                return "SM2";
            }
            // 标准 PRIVATE KEY：读算法 OID 判断
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(po.getContent());
            AlgorithmIdentifier algId = pki.getPrivateKeyAlgorithm();
            ASN1ObjectIdentifier alg = algId.getAlgorithm();
            if (Sm2Util.OID_SM2_PUBLIC_KEY.equals(alg.getId())) {
                return "SM2";
            }
            if ("1.2.840.10045.2.1".equals(alg.getId())) {
                // id-ecPublicKey：需再看曲线参数——SM2 曲线（1.2.156.10197.1.301）为 SM2，
                // 其它为 ECC（兼容第三方工具导出的标准 PKCS#8 国密密钥）
                ASN1Encodable params = algId.getParameters();
                if (params != null) {
                    ASN1Primitive p = params.toASN1Primitive();
                    if (p instanceof ASN1ObjectIdentifier
                            && Sm2Util.OID_SM2_PUBLIC_KEY.equals(((ASN1ObjectIdentifier) p).getId())) {
                        return "SM2";
                    }
                }
                return "ECC";
            }
            if ("1.2.840.113549.1.1.1".equals(alg.getId())) {
                return "RSA"; // rsaEncryption（标准 PKCS#8 RSA 私钥）
            }
            if ("1.2.840.113549.1.1.10".equals(alg.getId())) {
                return "RSA-PSS"; // rsassaPss
            }
            if ("1.2.840.10040.4.1".equals(alg.getId())) {
                return "DSA"; // id-dsa
            }
            if ("1.3.101.112".equals(alg.getId()) || "1.3.101.113".equals(alg.getId())) {
                return "EdDSA"; // Ed25519 / Ed448（RFC 8410）
            }
            if (isPqcOid(alg.getId())) {
                return "PQC";
            }
            // 未知算法：保留原行为按 ECC 兜底（调用方会因密钥不匹配而显式报错）
            return "ECC";
        }
        return null;
    }

    // ============================ 内部工具 ============================

    /**
     * 判断算法 OID 是否属于 PQC（后量子）算法族。
     * ML-DSA / SLH-DSA / ML-KEM / Falcon / XMSS 等（RFC 8708 / NIST PQC 标准 OID）。
     */
    public static boolean isPqcOid(String oid) {
        if (oid == null) {
            return false;
        }
        // ML-DSA：2.16.840.1.101.3.4.3.17/18/19（SPKI）与 1.3.6.1.5.5.7.6.30（私钥弧）
        // SLH-DSA：2.16.840.1.101.3.4.3.14/15/16 与 1.3.6.1.5.5.7.6.31
        // ML-KEM：2.16.840.1.101.3.4.4.* 与 1.3.6.1.5.5.7.6.32
        return oid.startsWith("2.16.840.1.101.3.4.3.1")   // 14..19 SLH-DSA/ML-DSA
                || oid.startsWith("2.16.840.1.101.3.4.4.") // ML-KEM
                || oid.startsWith("1.3.6.1.5.5.7.6.30")     // ML-DSA 私钥弧
                || oid.startsWith("1.3.6.1.5.5.7.6.31")     // SLH-DSA 私钥弧
                || oid.startsWith("1.3.6.1.5.5.7.6.32")     // ML-KEM 私钥弧
                || oid.startsWith("1.3.101.113")            // Falcon 候选
                || oid.startsWith("1.3.101.110")            // XMSS
                || oid.startsWith("0.4.0.127.0.15.1.1.13"); // McEliece（Go 标准）
    }

    /** 判断算法名是否为 PQC（BC 返回的公钥/私钥算法名）。 */
    public static boolean isPqcAlgName(String alg) {
        if (alg == null) {
            return false;
        }
        String u = alg.toUpperCase();
        return u.contains("ML-DSA") || u.contains("SLH-DSA") || u.contains("ML-KEM")
                || u.contains("SPHINCS") || u.contains("DILITHIUM") || u.contains("KYBER")
                || u.contains("FALCON") || u.contains("XMSS") || u.contains("MCELIECE")
                || u.contains("RAINBOW") || u.contains("BIKE") || u.contains("HQC")
                || u.contains("SNTRU") || u.contains("LAKE");
    }

    /** 按 OID 查曲线位宽，查不到默认 256。 */
    private static int lookupCurveBitLength(ASN1ObjectIdentifier oid) {
        try {
            X9ECParameters x9 = ECNamedCurveTable.getByOID(oid);
            if (x9 != null) {
                return x9.getN().bitLength();
            }
        } catch (Exception ignored) {
        }
        return 256;
    }

    /** 读取文件并解析为单个 PemObject。 */
    private static PemObject readPemObject(String path) throws Exception {
        String text = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        try (PemReader reader = new PemReader(new StringReader(text))) {
            return reader.readPemObject();
        }
    }

    /** 把 PemObject 写出到文件（原子写：tmp → fsync → 备份 → move，避免断电/并发读到半截文件）。 */
    private static void writePemObject(String path, PemObject po) throws Exception {
        Path out = Paths.get(path);
        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(po);
        }
        byte[] bytes = sw.toString().getBytes(StandardCharsets.UTF_8);
        atomicWrite(out, bytes);
    }

    /** POSIX 平台用于敏感文件的权限：仅属主可读写。 */
    private static final java.util.Set<java.nio.file.attribute.PosixFilePermission> OWNER_ONLY =
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");

    /** 原子写文件（对齐 CertsDB.rewriteAll：tmp → fsync → .bak → move）。
     *
     * <p>POSIX 平台上临时文件、备份文件与目标文件一律收紧为 600：临时文件若按默认
     * umask（常见 644）创建，私钥会在写入窗口内对同机其他用户可读；.bak 是旧私钥副本，
     * 同样必须收紧。Windows（NTFS 无 POSIX 权限）自动跳过。 */
    public static void atomicWrite(Path out, byte[] bytes) throws Exception {
        Path tmp = out.resolveSibling(out.getFileName() + ".tmp");
        Path bak = out.resolveSibling(out.getFileName() + ".bak");
        // 先以 600 建文件再写入（FileOutputStream 截断写不会改变已存在的权限）
        createOwnerOnly(tmp);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString())) {
            fos.write(bytes);
            fos.getFD().sync();
        }
        if (Files.exists(out)) {
            Files.copy(out, bak, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            createOwnerOnly(bak);
        }
        Files.move(tmp, out, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        createOwnerOnly(out);
    }

    /** 非 POSIX 文件系统（Windows NTFS）不支持权限设置：静默跳过，不影响写入结果。 */
    private static void createOwnerOnly(Path p) {
        try {
            if (Files.exists(p)) {
                Files.setPosixFilePermissions(p, OWNER_ONLY);
            } else {
                Files.createFile(p,
                        java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            }
        } catch (UnsupportedOperationException | java.io.IOException ignored) {
        }
    }
}
