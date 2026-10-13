package modpkica;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * RootGetCrl —— 签发吊销列表 CRL（对应 Go 版 cmd/rootgetcrl）。
 *
 * <p>遍历 CERTS.txt 中类型为 R（根）或 C（中间）的证书，对每一个颁发者：
 * <ul>
 *   <li>R 类型：从 PKI/ROOT/序列号.crt|.key 加载颁发者密钥对；</li>
 *   <li>C 类型：从 PKI/CA/序列号.crt|.key 加载颁发者密钥对；</li>
 * </ul>
 * 收集 CERTS.txt 中全部状态为 R（已吊销）的证书（序列号 / 吊销时间 / 吊销原因），
 * 用颁发者密钥对签名生成 CRL，输出：
 * <pre>
 *   PKI/WebPublic/CRL/序列号.crl     （PEM 格式 X509 CRL）
 *   PKI/WebPublic/CRL/序列号.der.crl （DER 原始格式）
 *   PKI/WebPublic/CRL/序列号.crl + 序列号.der.crl（多根模型，无 root.crl）
 * </pre>
 * CRL 的 thisUpdate=当前时间-24h，nextUpdate=当前时间+24h（对齐 Go 版）。
 */
public final class RootGetCrl {

    private RootGetCrl() {
    }

    public static void main(String[] args) throws Exception {
        run();
    }

    /** 供其它程序（如 MakeRoot / Admin）内部调用。 */
    public static void run() throws Exception {
        run(AppPaths.baseDir());
    }

    /** 供 ADMIN 内部调用：指定工作目录刷新 CRL。 */
    public static void run(String baseDir) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);

        String rootDir = baseDir + "/PKI/ROOT/";
        String caDir = baseDir + "/PKI/CA/";
        String webCrlDir = baseDir + "/PKI/WebPublic/CRL/";
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get(webCrlDir));

        int count = 0;
        for (CertsDB.CertEntry entry : db.getAll()) {
            if (entry.type == 'R' || entry.type == 'C') {
                generateCrl(entry, rootDir, caDir, webCrlDir, db);
                count++;
            }
        }
        System.out.println("CRL 生成完成，共处理颁发者 " + count + " 个");
    }

    private static void generateCrl(CertsDB.CertEntry issuer,
                                    String rootDir, String caDir, String webCrlDir,
                                    CertsDB db) throws Exception {
        // ---- 1. 加载颁发者证书与私钥 ----
        String issuerPath = issuer.type == 'R' ? rootDir : caDir;
        X509Certificate caCert = PemIO.readCert(issuerPath + issuer.serial + ".crt");
        AsymmetricKeyParameter akp = PemIO.readPrivateKey(issuerPath + issuer.serial + ".key");
        // BC 私钥参数 → JCA PrivateKey（CrlUtil 使用 JCA 接口）
        PrivateKey caKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(
                PrivateKeyInfoFactory.createPrivateKeyInfo(akp));
        // 配对校验：.key 与 .crt 必须是同一密钥对，否则会静默签出无法验证的 CRL
        CertUtil.assertKeyMatchesCert(caKey, caCert, "颁发者");

        // 签名算法族：必须按 CA 私钥实际类型决定（不能用证书签名算法判断——例如 RSA 根
        // 签发的 SM2 中间证书，其证书 SignatureAlgorithm 是 RSA，但 CA 自身密钥是 SM2，
        // CRL 必须用 CA 自身密钥签名，否则报 "BCECPrivateKey is not a RSAPrivateKey"）。
        String keyType = PemIO.detectKeyType(issuerPath + issuer.serial + ".key");
        // RSA-PSS：RSA 私钥文件无法区分 PSS，须按 CERTS.txt 登记算法列判断
        if ("RSA-PSS".equalsIgnoreCase(issuer.algo)) {
            keyType = "RSA-PSS";
        }
        // 哈希：SM2 固定 SM3；RSA/ECC 沿用证书签名算法中的哈希（对齐 Go 版）
        String hash = "SM2".equalsIgnoreCase(keyType) ? "sm3" : certHashFromSigAlg(caCert);

        // ---- 2. 收集全部已吊销证书（状态 R） ----
        Date thisUpdate = Date.from(java.time.Instant.now().minusSeconds(24 * 3600));
        Date nextUpdate = Date.from(java.time.Instant.now().plusSeconds(24 * 3600));

        List<CertsDB.CertEntry> all = db.getAll();
        List<CrlUtil.RevokedCert> revoked = new ArrayList<>();
        for (CertsDB.CertEntry e : all) {
            // CRL 属于具体颁发者：只收集该 issuer 签发的已吊销证书
            // （自签根证书 issuerId == 自身序列号，天然匹配；避免混入其它颁发者的吊销条目）
            if (e.status == 'R' && e.issuerId != null
                    && e.issuerId.equalsIgnoreCase(issuer.serial)) {
                BigInteger serial = new BigInteger(e.serial, 16);
                Date revTime = parseModTime(e.time);
                revoked.add(new CrlUtil.RevokedCert(serial, revTime, e.reason));
            }
        }

        // RFC 5280 5.2.3: cRLNumber 单调递增，历史序号持久化于 PKI/WebPublic/CRL/num.txt
        byte[] aki = CertUtil.getSubjectKeyIdentifier(caCert.getPublicKey());
        BigInteger crlNumber = nextCrlNumber(webCrlDir, issuer.serial,
                org.bouncycastle.util.encoders.Hex.toHexString(aki));

        byte[] der = CrlUtil.generateCrl(caCert, caKey, revoked, thisUpdate, nextUpdate,
                keyType, hash, crlNumber);
        String pem = CrlUtil.derToPem(der);
        // 原子写（tmp → fsync → .bak → move）：CRL 被依赖方直接消费，
        // 崩溃/并发下绝不能出现截断文件（旧实现两条裸 Files.write 存在该风险）
        PemIO.atomicWrite(java.nio.file.Paths.get(webCrlDir + issuer.serial + ".der.crl"), der);
        PemIO.atomicWrite(java.nio.file.Paths.get(webCrlDir + issuer.serial + ".crl"),
                pem.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println("CRL 已生成: " + issuer.serial + " (算法 " + keyType + "/" + hash
                + ", 吊销 " + revokedCount(issuer, all) + " 条)");
    }

    private static int revokedCount(CertsDB.CertEntry issuer, List<CertsDB.CertEntry> all) {
        int n = 0;
        for (CertsDB.CertEntry e : all) {
            if (e.status == 'R' && e.issuerId != null
                    && e.issuerId.equalsIgnoreCase(issuer.serial)) {
                n++;
            }
        }
        return n;
    }

    /** 读取/递增 CRL 顺序号（RFC 5280 5.2.3）。
     *  历史序号存储于 &lt;webCrlDir&gt;/num.txt，行格式（# 开头为注释）：
     *  &lt;颁发者证书序列号&gt; &lt;颁发者密钥标识符hex&gt; &lt;CRL顺序号&gt;
     *  例如: A000001 ABCDABCDABCDABCD... 1
     *  未登记过该颁发者时从 1 起始；每次发布递增 1。读改写在同一个
     *  synchronized 块内完成，避免并发生成 CRL 时序号重复。 */
    private static synchronized BigInteger nextCrlNumber(String webCrlDir,
                                                         String issuerSerial,
                                                         String akiHex) throws Exception {
        java.nio.file.Path p = java.nio.file.Paths.get(webCrlDir, "num.txt");
        // P2-13：读-改-写整体放入跨进程文件锁（num.txt.lock），写盘走 tmp+fsync+原子替换
        java.nio.file.Path lockPath = java.nio.file.Paths.get(webCrlDir, "num.txt.lock");
        try (java.nio.channels.FileChannel lc = java.nio.channels.FileChannel.open(lockPath,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
             java.nio.channels.FileLock fl = lc.lock()) {
            if (!fl.isValid()) {
                throw new java.io.IOException("CRL num.txt lock invalid");
            }
        java.util.List<String> original = new ArrayList<>();
        java.math.BigInteger current = java.math.BigInteger.ZERO;
        boolean found = false;
        if (java.nio.file.Files.exists(p)) {
            original = java.nio.file.Files.readAllLines(p,
                    java.nio.charset.StandardCharsets.UTF_8);
            for (String raw : original) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] cols = line.split("\\s+");
                if (cols.length >= 3 && cols[0].equals(issuerSerial)) {
                    try {
                        current = new BigInteger(cols[2].trim());
                        found = true;
                    } catch (NumberFormatException ignore) {
                    }
                }
            }
        }
        java.math.BigInteger next = current.add(java.math.BigInteger.ONE);
        StringBuilder sb = new StringBuilder();
        boolean replaced = false;
        for (String raw : original) {
            String line = raw.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                String[] cols = line.split("\\s+");
                if (cols.length >= 3 && cols[0].equals(issuerSerial)) {
                    sb.append(issuerSerial).append(" ").append(akiHex).append(" ")
                            .append(next).append("\r\n");
                    replaced = true;
                    continue;
                }
            }
            sb.append(raw).append("\r\n");
        }
        if (!replaced) {
            sb.append(issuerSerial).append(" ").append(akiHex).append(" ")
                    .append(next).append("\r\n");
        }
        java.nio.file.Path tmp = java.nio.file.Paths.get(webCrlDir, "num.txt.tmp");
        java.nio.file.Files.write(tmp, sb.toString().getBytes(
                java.nio.charset.StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp.toString(), true)) {
            fos.getFD().sync();
        }
        java.nio.file.Files.move(tmp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return next;
        } // end of file lock
    }

    /** CERTS.txt 内部时间（本地时间）转 Date。
     *  台账由 CertsDB 以 {@code LocalDateTime.now()} 按本机时区写入，读取必须用同一时区；
     *  若按固定 UTC+8 解析，非 UTC+8 主机会得到偏移的吊销时间（可能晚于 producedAt）。 */
    private static Date parseModTime(LocalDateTime t) {
        return Date.from(t.atZone(java.time.ZoneId.systemDefault()).toInstant());
    }

    /** 由证书签名算法 OID 推导哈希算法。 */
    private static String certHashFromSigAlg(X509Certificate cert) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(cert.getSigAlgOID());
        // RSASSA-PSS: 1.2.840.113549.1.1.10 → 从 PSS 参数 hashAlgorithm 推导哈希
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.10"))) {
            return pssHashFromSigParams(cert);
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.156.10197.1.501"))) {
            return "sm3";
        }
        // RSA: 1.2.840.113549.1.1.{5,11,12,13}
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"))) {
            return "sha1";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"))) {
            return "sha256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.12"))) {
            return "sha384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.13"))) {
            return "sha512";
        }
        // RSA-SHA3: 2.16.840.1.101.3.4.3.{1,2,3,4}
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.1"))) {
            return "sha3-224";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.2"))) {
            return "sha3-256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.3"))) {
            return "sha3-384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.4"))) {
            return "sha3-512";
        }
        // ECDSA: 1.2.840.10045.4.1 / 4.3.2 / 4.3.3 / 4.3.4
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.1"))) {
            return "sha1";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"))) {
            return "sha256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.3"))) {
            return "sha384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.4"))) {
            return "sha512";
        }
        // ECDSA-SHA3: 2.16.840.1.101.3.4.3.{9,10,11,12}
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.9"))) {
            return "sha3-224";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.10"))) {
            return "sha3-256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.11"))) {
            return "sha3-384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.12"))) {
            return "sha3-512";
        }
        // DSA: SHA1withDSA 1.2.840.10040.4.3；dsa_with_sha224/256/384/512 2.16.840.1.101.3.4.3.{5,6,7,8}
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10040.4.3"))) {
            return "sha1";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.5"))) {
            return "sha224";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.6"))) {
            return "sha256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.7"))) {
            return "sha384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.8"))) {
            return "sha512";
        }
        // DSA-SHA3: 2.16.840.1.101.3.4.3.{13,14,15,16}
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.13"))) {
            return "sha3-224";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.14"))) {
            return "sha3-256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.15"))) {
            return "sha3-384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.16"))) {
            return "sha3-512";
        }
        return "sha256";
    }


    /** 从 RSASSA-PSS 证书签名参数（RSASSAPSSparams）解析哈希算法名。 */
    private static String pssHashFromSigParams(X509Certificate cert) {
        try {
            byte[] params = cert.getSigAlgParams();
            if (params != null) {
                org.bouncycastle.asn1.pkcs.RSASSAPSSparams pss =
                        org.bouncycastle.asn1.pkcs.RSASSAPSSparams.getInstance(params);
                String h = pss.getHashAlgorithm().getAlgorithm().getId();
                switch (h) {
                    case "1.3.14.3.2.26": return "sha1";
                    case "2.16.840.1.101.3.4.2.4": return "sha224";
                    case "2.16.840.1.101.3.4.2.1": return "sha256";
                    case "2.16.840.1.101.3.4.2.2": return "sha384";
                    case "2.16.840.1.101.3.4.2.3": return "sha512";
                    case "2.16.840.1.101.3.4.2.7": return "sha3-224";
                    case "2.16.840.1.101.3.4.2.8": return "sha3-256";
                    case "2.16.840.1.101.3.4.2.9": return "sha3-384";
                    case "2.16.840.1.101.3.4.2.10": return "sha3-512";
                    default: return "sha256";
                }
            }
        } catch (Exception ignore) { /* 参数缺失/解析失败回退 sha256 */ }
        return "sha256";
    }

}