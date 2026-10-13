package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Locale;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * CertUtil —— 密钥对生成与 X.509 证书生成 / 签名工具。
 *
 * <p><b>签名算法自适应规则</b>（核心）：
 * <ul>
 *   <li>RSA 颁发者 → {@code SHAxxxWithRSA}（SHA1/SHA256/SHA384/SHA512）</li>
 *   <li>ECC 颁发者 → {@code ECDSAWithSHAxxx}</li>
 *   <li>SM2 颁发者 → {@code SM3withSM2}（固定 SM3 摘要）</li>
 * </ul>
 *
 * <p>SM2 签名必须用自定义 {@link SM2ContentSigner}：BC 标准 ContentSigner 走 JCA
 * 时不会按 GB/T 32918 计算 ZA，因此这里手动用 {@link SM2Signer} +
 * {@link ParametersWithID}（默认用户 ID）来完成 {@code e=SM3(ZA||TBS)}。
 */
public final class CertUtil {

    /** 摘要名称集合，便于归一化 */
    private static final Set<String> HASH_NAMES = new HashSet<>();

    /** 注册 BC Provider（类加载时执行，所有程序入口都会用到本类） */
    static {
        Bc.init();
        HASH_NAMES.add("SHA1");
        HASH_NAMES.add("SHA-1");
        HASH_NAMES.add("SHA256");
        HASH_NAMES.add("SHA-256");
        HASH_NAMES.add("SHA384");
        HASH_NAMES.add("SHA-384");
        HASH_NAMES.add("SHA512");
        HASH_NAMES.add("SHA-512");
        HASH_NAMES.add("SHA3-224");
        HASH_NAMES.add("SHA3-256");
        HASH_NAMES.add("SHA3-384");
        HASH_NAMES.add("SHA3-512");
        HASH_NAMES.add("SM3");
    }

    private CertUtil() {
    }

    // ============================ 密钥对生成 ============================

    /** 生成 RSA 密钥对。 */
    public static KeyPair generateRsaKeyPair(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(bits, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /**
     * 生成 ECC 密钥对（224/256/384/521，对应 secp224r1/secp256r1/secp384r1/secp521r1）。
     */
    public static KeyPair generateEccKeyPair(int bits) throws Exception {
        String curve;
        switch (bits) {
            case 224:
                curve = "secp224r1";
                break;
            case 384:
                curve = "secp384r1";
                break;
            case 521:
                curve = "secp521r1";
                break;
            case 256:
            default:
                curve = "secp256r1";
                break;
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    /** 生成 SM2 密钥对（sm2p256v1）。 */
    public static KeyPair generateSm2KeyPair() throws Exception {
        return Sm2Util.generateSm2JcaKeyPair();
    }

    /**
     * 生成 DSA 密钥对（FIPS 186-4：1024/2048/3072 位，L=1024..3072 且为 64 的倍数）。
     * BC 的 DSA KeyPairGenerator 不接受任意非标准长度，按三档归一。
     */
    public static KeyPair generateDsaKeyPair(int bits) throws Exception {
        int b;
        if (bits >= 3072) {
            b = 3072;
        } else if (bits >= 2048) {
            b = 2048;
        } else {
            b = 1024;
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", "BC");
        kpg.initialize(b, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** 生成 Ed25519 密钥对（RFC 8032，固定 256 位，无密钥位数参数）。 */
    public static KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        return kpg.generateKeyPair();
    }

    /**
     * 生成 ML-DSA（FIPS 204）PQC 密钥对。
     *
     * @param spec 规格字符串，接受 "ML-DSA-44"/"ML-DSA-65"/"ML-DSA-87"（也兼容 "44"/"65"/"87" 等）
     */
    public static KeyPair generatePqcKeyPair(String spec) throws Exception {
        String s = normalizePqcSpec(spec);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(s, "BC");
        kpg.initialize(MLDSAParameterSpec.fromName(s));
        return kpg.generateKeyPair();
    }

    /** 归一化 ML-DSA 规格为 BC 算法名（ML-DSA-44/65/87），非法输入回退 ML-DSA-65。 */
    public static String normalizePqcSpec(String spec) {
        if (spec == null) {
            return "ML-DSA-65";
        }
        String s = spec.trim().toUpperCase(Locale.ROOT).replace(" ", "").replace("_", "-");
        switch (s) {
            case "44":
            case "ML-DSA-44":
                return "ML-DSA-44";
            case "87":
            case "ML-DSA-87":
                return "ML-DSA-87";
            case "65":
            case "ML-DSA-65":
            default:
                return "ML-DSA-65";
        }
    }

    // ============================ 签名算法 OID ============================

    /**
     * 根据颁发者密钥类型与摘要返回签名算法 OID。
     *
     * @param keyType "RSA" / "ECC" / "SM2" / "DSA" / "EdDSA" / "PQC"
     * @param hash   摘要名（RSA/ECC/DSA 时使用；SM2 忽略固定 SM3；EdDSA/PQC 忽略）
     */
    public static ASN1ObjectIdentifier getSignatureAlgOid(String keyType, String hash) {
        if ("SM2".equalsIgnoreCase(keyType)) {
            return new ASN1ObjectIdentifier(Sm2Util.OID_SM3_WITH_SM2);
        }
        // EdDSA（Ed25519）：RFC 8410 纯签名算法，无哈希参数，OID 固定 1.3.101.112
        if ("EdDSA".equalsIgnoreCase(keyType)) {
            return new ASN1ObjectIdentifier("1.3.101.112");
        }
        // PQC（ML-DSA 等）：签名算法 OID 即密钥算法 OID（内部自带哈希），按规格区分：
        // 2.16.840.1.101.3.4.3.17=ML-DSA-44 / .18=ML-DSA-65 / .19=ML-DSA-87（FIPS 204）
        if ("PQC".equalsIgnoreCase(keyType)) {
            switch (normalizePqcSpec(hash)) {
                case "ML-DSA-44":
                    return new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.17");
                case "ML-DSA-87":
                    return new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.19");
                case "ML-DSA-65":
                default:
                    return new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.18");
            }
        }
        String h = normalizeHash(hash);
        if ("RSA".equalsIgnoreCase(keyType)) {
            switch (h) {
                case "SHA1":
                    return new ASN1ObjectIdentifier("1.2.840.113549.1.1.5");
                case "SHA224":
                    return new ASN1ObjectIdentifier("1.2.840.113549.1.1.14");
                case "SHA384":
                    return new ASN1ObjectIdentifier("1.2.840.113549.1.1.12");
                case "SHA512":
                    return new ASN1ObjectIdentifier("1.2.840.113549.1.1.13");
                case "SHA3-224":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_rsassa_pkcs1_v1_5_with_sha3_224.getId());
                case "SHA3-256":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_rsassa_pkcs1_v1_5_with_sha3_256.getId());
                case "SHA3-384":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_rsassa_pkcs1_v1_5_with_sha3_384.getId());
                case "SHA3-512":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_rsassa_pkcs1_v1_5_with_sha3_512.getId());
                case "SHA256":
                default:
                    return new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
            }
        }
        if ("DSA".equalsIgnoreCase(keyType)) {
            switch (h) {
                case "SHA1":
                    return new ASN1ObjectIdentifier("1.2.840.10040.4.3");
                case "SHA224":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .dsa_with_sha224.getId());
                case "SHA256":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .dsa_with_sha256.getId());
                case "SHA384":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .dsa_with_sha384.getId());
                case "SHA512":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .dsa_with_sha512.getId());
                case "SHA3-224":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_dsa_with_sha3_224.getId());
                case "SHA3-256":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_dsa_with_sha3_256.getId());
                case "SHA3-384":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_dsa_with_sha3_384.getId());
                case "SHA3-512":
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .id_dsa_with_sha3_512.getId());
                default:
                    return new ASN1ObjectIdentifier(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                    .dsa_with_sha256.getId());
            }
        }
        // ECC
        switch (h) {
            case "SHA1":
                return new ASN1ObjectIdentifier("1.2.840.10045.4.1");
            case "SHA224":
                return new ASN1ObjectIdentifier("1.2.840.10045.4.3.1");
            case "SHA384":
                return new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
            case "SHA512":
                return new ASN1ObjectIdentifier("1.2.840.10045.4.3.4");
            case "SHA3-224":
                return new ASN1ObjectIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                .id_ecdsa_with_sha3_224.getId());
            case "SHA3-256":
                return new ASN1ObjectIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                .id_ecdsa_with_sha3_256.getId());
            case "SHA3-384":
                return new ASN1ObjectIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                .id_ecdsa_with_sha3_384.getId());
            case "SHA3-512":
                return new ASN1ObjectIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers
                                .id_ecdsa_with_sha3_512.getId());
            case "SHA256":
            default:
                return new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
        }
    }

    /**
     * 归一化摘要名为 SHA1/SHA224/SHA256/SHA384/SHA512/SHA3-224/SHA3-256/SHA3-384/SHA3-512/SM3。
     * SHA3 系列必须保留连字符（JCA 算法名 SHA3-256withRSA），其余沿用旧逻辑去掉连字符。
     */
    private static String normalizeHash(String hash) {
        if (hash == null) {
            return "SHA256";
        }
        String u = hash.toUpperCase(Locale.ROOT);
        if (u.startsWith("SHA3")) {
            switch (u.replace("_", "-").replace(" ", "")) {
                case "SHA3-224":
                    return "SHA3-224";
                case "SHA3-256":
                    return "SHA3-256";
                case "SHA3-384":
                    return "SHA3-384";
                case "SHA3-512":
                    return "SHA3-512";
                default:
                    return "SHA3-256";
            }
        }
        switch (u.replace("-", "")) {
            case "SHA1":
                return "SHA1";
            case "SHA224":
                return "SHA224";
            case "SHA256":
                return "SHA256";
            case "SHA384":
                return "SHA384";
            case "SHA512":
                return "SHA512";
            case "SM3":
                return "SM3";
            default:
                return "SHA256";
        }
    }

    // ============================ ContentSigner ============================

    /**
     * 读取 PEM 私钥文件并转为 JCA PrivateKey（RSA/ECC/SM2 通用）。
     *
     * <p>内部通过 {@code JcaPEMKeyConverter} 把 BC 的 AsymmetricKeyParameter
     * 转为 JCA PrivateKey，供 JcaContentSignerBuilder 等使用。
     */
    public static PrivateKey readJcaPrivateKey(String path) throws Exception {
        org.bouncycastle.crypto.params.AsymmetricKeyParameter akp = PemIO.readPrivateKey(path);
        return new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC")
                .getPrivateKey(org.bouncycastle.crypto.util.PrivateKeyInfoFactory
                        .createPrivateKeyInfo(akp));
    }

    /**
     * 校验私钥与证书公钥是否配对——"文件存在"不等于"是同一个密钥对"。
     *
     * <p>用该密钥对做一次"私钥签名 → 证书公钥验签"闭环，天然覆盖
     * RSA / RSA-PSS / ECC / SM2 / EdDSA / DSA / PQC(ML-DSA) 等全部算法，
     * 无需按算法解析密钥结构。不匹配时抛 IllegalStateException，防止误配的
     * .key 文件（换错/损坏）静默签出无法链式验证的证书或 CRL。
     *
     * @param key  私钥（应为证书对应私钥）
     * @param cert 证书（提供公钥）
     * @param what 角色描述，用于错误信息（如 "颁发者"）
     */
    public static void assertKeyMatchesCert(PrivateKey key, X509Certificate cert, String what) {
        PublicKey pub = cert.getPublicKey();
        String sigAlg = probeSignatureAlgorithm(pub);
        if (sigAlg == null) {
            System.out.println("[警告] 无法校验" + what + "私钥与证书是否配对（公钥算法 "
                    + pub.getAlgorithm() + "），已跳过检查");
            return;
        }
        try {
            byte[] probe = new byte[32];
            new SecureRandom().nextBytes(probe);
            java.security.Signature s = java.security.Signature.getInstance(sigAlg, "BC");
            s.initSign(key);
            s.update(probe);
            byte[] sig = s.sign();
            s.initVerify(pub);
            s.update(probe);
            if (!s.verify(sig)) {
                throw new IllegalStateException(what + "私钥与证书公钥不匹配："
                        + "请确认该 ID 对应的 .key 与 .crt 来自同一密钥对");
            }
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            // 算法名在本 Provider 不支持等：告警放行，避免新算法被误拦
            System.out.println("[警告] " + what + "私钥与证书配对校验无法执行（"
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + "），已跳过");
        }
    }

    /** 按公钥类型选择配对校验用签名算法；无法确定返回 null。 */
    private static String probeSignatureAlgorithm(PublicKey pub) {
        String alg = pub.getAlgorithm() == null ? "" : pub.getAlgorithm().toUpperCase(Locale.ROOT);
        if (alg.contains("RSA")) {
            return "SHA256withRSA";
        }
        if (alg.contains("EC") || alg.contains("ECDSA")) {
            // BC 对 SM2 密钥也报告 "EC"，必须按曲线区分：SM2 用 SM3withSM2
            return isSm2PublicKey(pub) ? "SM3withSM2" : "SHA256withECDSA";
        }
        if (alg.contains("DSA")) {
            return "SHA256withDSA";
        }
        if (alg.contains("ED25519")) {
            return "Ed25519";
        }
        if (alg.contains("ED448")) {
            return "Ed448";
        }
        if (PemIO.isPqcAlgName(alg)) {
            return pub.getAlgorithm(); // ML-DSA 等纯签名算法：算法名即签名算法名
        }
        return null;
    }

    /** 判断公钥是否为 SM2 曲线（BC 对 SM2 也报告 "EC"，须按曲线名/阶区分）。 */
    static boolean isSm2PublicKey(PublicKey pub) {
        if (!(pub instanceof java.security.interfaces.ECPublicKey)) {
            return false;
        }
        try {
            java.security.spec.ECParameterSpec spec =
                    ((java.security.interfaces.ECPublicKey) pub).getParams();
            if (spec instanceof ECNamedCurveSpec) {
                String name = ((ECNamedCurveSpec) spec).getName();
                return name != null && name.toLowerCase(Locale.ROOT).contains("sm2");
            }
            // 退化判断：SM2 推荐曲线的阶
            return new BigInteger(
                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
                    .equals(spec.getOrder());
        } catch (Exception ignore) {
            return false;
        }
    }

    /**
     * 根据颁发者私钥与算法类型构造 ContentSigner。
     * SM2 时返回自定义 {@link SM2ContentSigner}。
     *
     * @param key     颁发者私钥（JCA PrivateKey）
     * @param keyType "RSA" / "ECC" / "SM2"
     * @param hash    摘要名
     */
    public static ContentSigner createContentSigner(PrivateKey key, String keyType, String hash)
            throws OperatorCreationException {
        if ("SM2".equalsIgnoreCase(keyType)) {
            // JCA 私钥 -> ECPrivateKeyParameters
            ECPrivateKeyParameters priv = Sm2Util.toEcPrivateParams(key);
            return new SM2ContentSigner(priv);
        }
        // PQC（ML-DSA/SLH-DSA 等）：纯签名算法，内部自带哈希，算法名即私钥算法名（如 ML-DSA-65）
        if ("PQC".equalsIgnoreCase(keyType) || PemIO.isPqcAlgName(key.getAlgorithm())) {
            return new JcaContentSignerBuilder(key.getAlgorithm()).setProvider("BC").build(key);
        }
        // EdDSA（Ed25519）：RFC 8032 纯签名算法，签名算法名即私钥算法名，不带任何哈希
        if ("EdDSA".equalsIgnoreCase(keyType)) {
            return new JcaContentSignerBuilder(key.getAlgorithm()).setProvider("BC").build(key);
        }
        // DSA：SHAxxxwithDSA（BC 支持 SHA1/SHA224/SHA256/SHA384/SHA512/SHA3-xxx）
        if ("DSA".equalsIgnoreCase(keyType)) {
            String hd = normalizeHash(hash);
            return new JcaContentSignerBuilder(hd + "withDSA").setProvider("BC").build(key);
        }
        String h = normalizeHash(hash);
        String jcaAlg;
        if ("RSA".equalsIgnoreCase(keyType)) {
            jcaAlg = h.startsWith("SHA3") ? h + "withRSA" : h.toLowerCase() + "WITHRSA";
        } else if ("RSA-PSS".equalsIgnoreCase(keyType)) {
            // RSASSA-PSS (RFC 4055 / RFC 8017): BC *withRSAandMGF1 自动生成
            // RSASSA-PSS AlgorithmIdentifier (hashAlgorithm=本摘要, MGF1=同摘要,
            // saltLength=摘要长度, trailerField=1), 符合标准默认参数。
            jcaAlg = h + "withRSAandMGF1";
        } else {
            // ECC（标准椭圆曲线）只支持 SHA1/SHA224/SHA256/SHA384/SHA512/SHA3-xxx；
            // SM3withECDSA 仅对 SM2 曲线（sm2p256v1）有效，对普通 ECC 报 Unknown signature type
            if ("sm3".equals(h.toLowerCase())) {
                throw new OperatorCreationException(
                        "ECC 类型证书不支持 SM3 摘要（SM3 仅用于 SM2 国密），请改用 SHA256/SHA384/SHA512");
            }
            jcaAlg = h.startsWith("SHA3") ? h + "withECDSA" : h.toLowerCase() + "WITHECDSA";
        }
        return new JcaContentSignerBuilder(jcaAlg).setProvider("BC").build(key);
    }

    /**
     * SM2 专用 ContentSigner。
     *
     * <p>BC 的 JcaContentSignerBuilder("SM3withSM2") 不保证按 GB/T 32918 计算 ZA，
     * 这里直接用 SM2Signer + ParametersWithID（默认用户ID），对 getOutputStream()
     * 收到的 TBS 原文计算 e=SM3(ZA||TBS)，输出 DER(r,s)。
     */
    public static class SM2ContentSigner implements ContentSigner {
        private final AlgorithmIdentifier algId;
        private final SM2Signer signer = new SM2Signer();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public SM2ContentSigner(ECPrivateKeyParameters priv) {
            this.algId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(Sm2Util.OID_SM3_WITH_SM2), DERNull.INSTANCE);
            // 外层 ParametersWithID，内层 ParametersWithRandom
            ParametersWithID p = new ParametersWithID(
                    new ParametersWithRandom(priv, new SecureRandom()),
                    Sm2Util.getSm2UidBytes());
            signer.init(true, p);
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algId;
        }

        @Override
        public OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            byte[] msg = buffer.toByteArray();
            // 关键：每次取签名后必须清空输入缓冲并复位签名器——
            // SCT 流程（预证书 -> 最终证书）复用同一 ContentSigner 构建两次，
            // 不清空会导致第二次签名基于 预证书TBS+最终TBS 拼接，签名无效。
            buffer.reset();
            signer.reset();
            signer.update(msg, 0, msg.length);
            try {
                return signer.generateSignature();
            } catch (org.bouncycastle.crypto.CryptoException e) {
                throw new IllegalStateException("SM2 签名失败", e);
            }
        }
    }

    // ============================ SubjectKeyIdentifier ============================

    /**
     * 计算公钥的 SubjectKeyIdentifier：对公钥 SubjectPublicKeyInfo 中的
     * subjectPublicKey 位串做 SHA-1（RFC5280 方法 1）。
     */
    public static byte[] getSubjectKeyIdentifier(PublicKey pubKey) throws Exception {
        // pubKey.getEncoded() 即 SubjectPublicKeyInfo DER
        byte[] spki = pubKey.getEncoded();
        // 解析出 subjectPublicKey 的原始位串内容
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo info =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(spki);
        byte[] keyBits = info.getPublicKeyData().getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(keyBits);
    }

    // ============================ 证书生成 ============================

    /**
     * 生成自签名根证书。
     *
     * @param subject   主体 DN
     * @param kp        根密钥对
     * @param serial    序列号
     * @param notBefore 生效起
     * @param notAfter  生效止
     * @param keyType   "RSA" / "ECC" / "SM2"
     * @param hash      摘要名
     */
    public static X509Certificate buildSelfSignedRoot(X500Principal subject, KeyPair kp,
                                                      BigInteger serial, Date notBefore, Date notAfter,
                                                      String keyType, String hash) throws Exception {
        ContentSigner signer = createContentSigner(kp.getPrivate(), keyType, hash);
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());

        // KeyUsage: 证书签名 + CRL 签名
        cb.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // BasicConstraints: 根 CA（无 pathLen 限制，对齐 Go 版）
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // SubjectKeyIdentifier
        cb.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(getSubjectKeyIdentifier(kp.getPublic())));
        // 自签根：AKI 等于 SKI
        cb.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(getSubjectKeyIdentifier(kp.getPublic())));

        X509CertificateHolder holder = cb.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /**
     * 由颁发者签发一张证书（终端或中间 CA）。
     *
     * @param issuerCert 颁发者证书
     * @param issuerKey  颁发者私钥
     * @param subject    使用者
     * @param subjectPub 使用者公钥
     * @param serial     序列号
     * @param notBefore  生效起
     * @param notAfter   生效止
     * @param keyType    颁发者类型 "RSA" / "ECC" / "SM2"
     * @param hash       摘要名
     * @param isCa       是否为 CA（true 则 BasicConstraints pathLen=0）
     * @param crlUrl     CRL 分发点（可为空）
     * @param ocspUrl    OCSP AIA（可为空）
     * @param caIssuerUrl caIssuers AIA（可为空）
     * @param cpsUri     CPS 策略 URI（可为空）
     * @param userNotice 用户通告文本（可为空）
     */
    public static X509Certificate buildSignedCert(X509Certificate issuerCert, PrivateKey issuerKey,
                                                   X500Principal subject, PublicKey subjectPub,
                                                   BigInteger serial, Date notBefore, Date notAfter,
                                                   String keyType, String hash, boolean isCa,
                                                   String crlUrl, String ocspUrl, String caIssuerUrl,
                                                   String cpsUri, String userNotice) throws Exception {
        ContentSigner signer = createContentSigner(issuerKey, keyType, hash);
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                issuerCert, serial, notBefore, notAfter, subject, subjectPub);

        // KeyUsage
        int usage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment;
        if (isCa) {
            usage = KeyUsage.keyCertSign | KeyUsage.cRLSign;
        }
        cb.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        // BasicConstraints：CA 无 pathLen 限制（对齐 Go 版，不启用 MaxPathLen）；非 CA 为 false
        cb.addExtension(Extension.basicConstraints, true,
                isCa ? new BasicConstraints(true) : new BasicConstraints(false));
        // SubjectKeyIdentifier
        byte[] ski = getSubjectKeyIdentifier(subjectPub);
        cb.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        // AuthorityKeyIdentifier（取颁发者公钥 SKI）
        byte[] aki = getSubjectKeyIdentifier(issuerCert.getPublicKey());
        cb.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(aki));

        // CRL 分发点
        if (crlUrl != null && !crlUrl.isEmpty()) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
            GeneralNames gn1 = new GeneralNames(gn);
            DistributionPoint dp = new DistributionPoint(
                    new DistributionPointName(DistributionPointName.FULL_NAME, gn1), null, null);
            cb.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{dp}));
        }

        // AuthorityInfoAccess: OCSP + caIssuers
        if ((ocspUrl != null && !ocspUrl.isEmpty()) || (caIssuerUrl != null && !caIssuerUrl.isEmpty())) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            if (ocspUrl != null && !ocspUrl.isEmpty()) {
                vec.add(new AccessDescription(AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
            }
            if (caIssuerUrl != null && !caIssuerUrl.isEmpty()) {
                vec.add(new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, caIssuerUrl)));
            }
            cb.addExtension(Extension.authorityInfoAccess, false,
                    AuthorityInformationAccess.getInstance(new DERSequence(vec)));
        }

        // CertificatePolicies(CPS + UserNotice)
        if (cpsUri != null && !cpsUri.isEmpty()) {
            cb.addExtension(Extension.certificatePolicies, false,
                    buildCpsPolicy(cpsUri, userNotice));
        }

        X509CertificateHolder holder = cb.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /**
     * 构造 CertificatePolicies 扩展值（PolicyInformation + CPS URI + UserNotice）。
     * 参考 Go 版 internal/cps/cps.go。
     */
    private static PolicyInformation buildCpsPolicy(String cpsUri, String userNotice) {
        // 策略 OID：MODPKICA 项目标准证书颁发策略（与签发证书/证书验证输出一致），
        // 限定符指向 CPS / UserNotice
        ASN1ObjectIdentifier policyOid =
                new ASN1ObjectIdentifier("1.3.6.1.4.1.4146.1.95");
        java.util.List<PolicyQualifierInfo> qualifiers = new java.util.ArrayList<>();

        // CPS URI（IA5String）：BC 便捷构造器自动使用 OID 1.3.6.1.5.5.7.2.1
        qualifiers.add(new PolicyQualifierInfo(cpsUri));

        // UserNotice（UTF8String）：OID 1.3.6.1.5.5.7.2.2
        if (userNotice != null && !userNotice.isEmpty()) {
            org.bouncycastle.asn1.x509.DisplayText dt =
                    new org.bouncycastle.asn1.x509.DisplayText(userNotice);
            org.bouncycastle.asn1.x509.UserNotice un =
                    new org.bouncycastle.asn1.x509.UserNotice(null, dt);
            qualifiers.add(new PolicyQualifierInfo(
                    new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"), un));
        }

        ASN1EncodableVector qvec = new ASN1EncodableVector();
        for (PolicyQualifierInfo q : qualifiers) {
            qvec.add(q);
        }
        return new PolicyInformation(policyOid, new DERSequence(qvec));
    }
}
