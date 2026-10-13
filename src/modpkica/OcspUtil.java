package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * OcspUtil —— OCSP 请求解析与响应生成（RFC 6960）。
 *
 * <p><b>请求解析</b>：用 BC 的 {@link OCSPReq} 提取 CertID 的哈希算法 OID、
 * issuerNameHash、issuerKeyHash、序列号，以及 Nonce 扩展（OID 1.3.6.1.5.5.7.48.1.2）。
 *
 * <p><b>RSA/ECC 响应</b>：用 BC 的 {@link BasicOCSPRespBuilder} + {@link OCSPRespBuilder}。
 * CertID 的哈希算法按请求回显；ResponderID 用 responderCert 的 Subject（Name 形式）。
 *
 * <p><b>SM2 响应</b>：BC 的 OCSP builder 不支持 SM2 签名，因此按 Go 版
 * {@code smocsp.go CreateResponse} 手动构造 ASN.1：responseData(TBS) → SM2 签名 →
 * basicResponse → OCSPResponse。签名算法 OID 固定 1.2.156.10197.1.501。
 *
 * <p>时间约定：ThisUpdate = now-10min，NextUpdate = now+10min，ProducedAt = now（截断到分钟）。
 * Nonce 放在<b>全局</b> responseExtensions，不放进 singleExtensions。
 */
public final class OcspUtil {

    /** 注册 BC Provider */
    static {
        Bc.init();
    }

    /** Nonce 扩展 OID：1.3.6.1.5.5.7.48.1.2 */
    public static final String OID_NONCE = "1.3.6.1.5.5.7.48.1.2";
    /** id-pkix-ocsp-basic */
    public static final ASN1ObjectIdentifier OID_BASIC =
            OCSPObjectIdentifiers.id_pkix_ocsp_basic;

    /** 证书状态：正常 */
    public static final int GOOD = 0;
    /** 证书状态：已吊销 */
    public static final int REVOKED = 1;
    /** 证书状态：未知 */
    public static final int UNKNOWN = 2;

    private OcspUtil() {
    }

    /**
     * 解析后的 OCSP 请求。
     */
    public static class OcspRequest {
        /** CertID 哈希算法 OID */
        public String hashAlgOid;
        /** issuerNameHash */
        public byte[] issuerNameHash;
        /** issuerKeyHash */
        public byte[] issuerKeyHash;
        /** 证书序列号 */
        public BigInteger serialNumber;
        /** Nonce 扩展的 raw 值（可能为 null） */
        public byte[] nonce;
    }

    /**
     * 解析 DER 编码的 OCSP 请求。
     */
    public static OcspRequest parseRequest(byte[] der) throws Exception {
        OCSPReq ocspReq = new OCSPReq(der);
        Req[] reqs = ocspReq.getRequestList();
        if (reqs == null || reqs.length == 0) {
            throw new IllegalArgumentException("OCSP 请求为空");
        }
        if (reqs.length > 1) {
            // 本服务只生成单证书响应：静默只回答 reqs[0] 会让客户端误以为其余 CertID
            // 也包含在响应里（RFC 6960 允许多请求，本服务显式拒绝而非漏答）
            throw new UnsupportedRequestException(
                    "不支持批量 OCSP 请求（CertID 数=" + reqs.length + "），请逐个证书请求");
        }
        CertificateID cid = reqs[0].getCertID();
        OcspRequest r = new OcspRequest();
        r.hashAlgOid = cid.getHashAlgOID().getId();
        r.issuerNameHash = cid.getIssuerNameHash();
        r.issuerKeyHash = cid.getIssuerKeyHash();
        r.serialNumber = cid.getSerialNumber();

        Extension nonceExt = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExt != null) {
            ASN1OctetString os = nonceExt.getExtnValue();
            r.nonce = os.getOctets();
        }
        return r;
    }

    /**
     * 统一入口：按颁发者密钥类型生成 OCSP 响应。
     *
     * @param keyType        "RSA" / "ECC" / "SM2"
     * @param issuerCert     签发该证书的 CA 证书
     * @param responderCert  OCSP 响应器证书
     * @param signer         ContentSigner（RSA/ECC 用）
     * @param sm2Priv        SM2 私钥参数（SM2 时用）
     * @param serial         目标证书序列号
     * @param hashAlgOid     回显的 CertID 哈希算法 OID
     * @param status         GOOD / REVOKED / UNKNOWN
     * @param reason         吊销原因（status=REVOKED 时有效）
     * @param revokedAt      吊销时间（status=REVOKED 时有效）
     * @param nonce          Nonce 值（可为 null）
     */
    public static byte[] createResponse(String keyType,
                                        X509Certificate issuerCert,
                                        X509Certificate responderCert,
                                        ContentSigner signer,
                                        org.bouncycastle.crypto.params.ECPrivateKeyParameters sm2Priv,
                                        BigInteger serial,
                                        String hashAlgOid,
                                        int status, int reason, Date revokedAt,
                                        byte[] nonce) throws Exception {
        Date now = new Date();
        Date thisUpdate = new Date(now.getTime() - 10 * 60 * 1000L);
        Date nextUpdate = new Date(now.getTime() + 10 * 60 * 1000L);
        // ProducedAt 截断到分钟
        long minuteMs = 60 * 1000L;
        Date producedAt = new Date((now.getTime() / minuteMs) * minuteMs);

        if ("SM2".equalsIgnoreCase(keyType)) {
            return createResponseSm2(issuerCert, responderCert, sm2Priv, serial,
                    hashAlgOid, status, reason, revokedAt,
                    thisUpdate, nextUpdate, producedAt, nonce);
        }
        return createResponseRsaEcc(issuerCert, responderCert, signer, serial,
                hashAlgOid, status, reason, revokedAt,
                thisUpdate, nextUpdate, producedAt, nonce);
    }

    // ============================ RSA / ECC ============================

    private static byte[] createResponseRsaEcc(X509Certificate issuerCert,
                                                X509Certificate responderCert,
                                                ContentSigner signer,
                                                BigInteger serial,
                                                String hashAlgOid,
                                                int status, int reason, Date revokedAt,
                                                Date thisUpdate, Date nextUpdate, Date producedAt,
                                                byte[] nonce) throws Exception {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgOid));
        // CertificateID 需要 DigestCalculator 来计算 issuerNameHash/issuerKeyHash
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        DigestCalculator dc = dcp.get(algId);
        CertificateID certId = new CertificateID(dc,
                new JcaX509CertificateHolder(issuerCert), serial);

        // ResponderID = responderCert 的 Subject（Name 形式）
        RespID respId = new RespID(X500Name.getInstance(
                responderCert.getSubjectX500Principal().getEncoded()));
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respId);

        CertificateStatus certStatus;
        if (status == REVOKED) {
            certStatus = new RevokedStatus(revokedAt, reason);
        } else if (status == UNKNOWN) {
            certStatus = new UnknownStatus();
        } else {
            certStatus = CertificateStatus.GOOD;
        }
        builder.addResponse(certId, certStatus, thisUpdate, nextUpdate);

        // Nonce -> 全局 responseExtensions
        if (nonce != null && nonce.length > 0) {
            Extension nonceExt = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                    false, new DEROctetString(nonce));
            builder.setResponseExtensions(new Extensions(nonceExt));
        }

        X509CertificateHolder[] chain = new X509CertificateHolder[]{
                new JcaX509CertificateHolder(responderCert)
        };
        BasicOCSPResp basic = builder.build(signer, chain, producedAt);
        OCSPResp resp = new OCSPRespBuilder().build(0, basic);
        return resp.getEncoded();
    }

    // ============================ SM2 手动 ASN.1 ============================

    private static byte[] createResponseSm2(X509Certificate issuerCert,
                                            X509Certificate responderCert,
                                            org.bouncycastle.crypto.params.ECPrivateKeyParameters sm2Priv,
                                            BigInteger serial,
                                            String hashAlgOid,
                                            int status, int reason, Date revokedAt,
                                            Date thisUpdate, Date nextUpdate, Date producedAt,
                                            byte[] nonce) throws Exception {
        // ---- CertID ----
        ASN1EncodableVector certIdVec = new ASN1EncodableVector();
        certIdVec.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgOid), DERNull.INSTANCE));
        // issuerNameHash / issuerKeyHash 由调用方请求里给出；这里按 issuer 证书重算
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(
                hashDigestName(hashAlgOid));
        byte[] issuerKeyHash = md.digest(
                new JcaX509CertificateHolder(issuerCert).getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        md.reset();
        byte[] issuerNameHash = md.digest(issuerCert.getSubjectX500Principal().getEncoded());
        certIdVec.add(new DEROctetString(issuerNameHash));
        certIdVec.add(new DEROctetString(issuerKeyHash));
        certIdVec.add(new org.bouncycastle.asn1.ASN1Integer(serial));
        DERSequence certId = new DERSequence(certIdVec);

        // ---- certStatus ----
        ASN1EncodableVector singleVec = new ASN1EncodableVector();
        singleVec.add(certId);
        if (status == REVOKED) {
            // RFC 6960：revoked [1] IMPLICIT RevokedInfo（内容不含 SEQUENCE 头）；
            // revocationReason 为 [0] EXPLICIT CRLReason。此前 CertStatus 误用 explicit
            // 导致 openssl/BC 按 IMPLICIT 解析错位（wrong tag / illegal object）。
            ASN1EncodableVector revokedInfo = new ASN1EncodableVector();
            revokedInfo.add(new ASN1GeneralizedTime(revokedAt));
            revokedInfo.add(new DERTaggedObject(true, 0, new ASN1Enumerated(reason)));
            singleVec.add(new DERTaggedObject(false, 1, new DERSequence(revokedInfo)));
        } else if (status == UNKNOWN) {
            singleVec.add(new DERTaggedObject(false, 2, DERNull.INSTANCE));
        } else {
            singleVec.add(new DERTaggedObject(false, 0, DERNull.INSTANCE));
        }
        singleVec.add(new ASN1GeneralizedTime(thisUpdate));
        singleVec.add(new DERTaggedObject(true, 0, new ASN1GeneralizedTime(nextUpdate)));
        DERSequence singleResponse = new DERSequence(singleVec);

        ASN1EncodableVector responsesVec = new ASN1EncodableVector();
        responsesVec.add(singleResponse);
        DERSequence responses = new DERSequence(responsesVec);

        // ---- responseData（TBS） ----
        ASN1EncodableVector tbsVec = new ASN1EncodableVector();
        // responderID [1] EXPLICIT Name（= responderCert Subject DER）
        byte[] subjectDer = responderCert.getSubjectX500Principal().getEncoded();
        tbsVec.add(new DERTaggedObject(true, 1, ASN1Primitive.fromByteArray(subjectDer)));
        tbsVec.add(new ASN1GeneralizedTime(producedAt));
        tbsVec.add(responses);
        // Nonce -> 全局 [1] EXPLICIT extensions
        if (nonce != null && nonce.length > 0) {
            Extension nonceExt = new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
            tbsVec.add(new DERTaggedObject(true, 1, new Extensions(nonceExt)));
        }
        DERSequence tbsResponseData = new DERSequence(tbsVec);
        byte[] tbsDer = tbsResponseData.getEncoded();

        // ---- SM2 签名 TBS ----
        byte[] signature = Sm2Util.sm2Sign(sm2Priv, tbsDer);

        // ---- basicResponse ----
        ASN1EncodableVector basicVec = new ASN1EncodableVector();
        basicVec.add(tbsResponseData);
        basicVec.add(new AlgorithmIdentifier(
                new ASN1ObjectIdentifier(Sm2Util.OID_SM3_WITH_SM2), DERNull.INSTANCE));
        basicVec.add(new DERBitString(signature));
        // 嵌入 responderCert：[0] EXPLICIT
        ASN1EncodableVector certsVec = new ASN1EncodableVector();
        certsVec.add(ASN1Primitive.fromByteArray(responderCert.getEncoded()));
        basicVec.add(new DERTaggedObject(true, 0, new DERSequence(certsVec)));
        DERSequence basicResponse = new DERSequence(basicVec);

        // ---- responseBytes [0] EXPLICIT { type, octet } ----
        ASN1EncodableVector rbVec = new ASN1EncodableVector();
        rbVec.add(OID_BASIC);
        rbVec.add(new DEROctetString(basicResponse));
        DERTaggedObject responseBytes = new DERTaggedObject(true, 0, new DERSequence(rbVec));

        // ---- OCSPResponse ----
        ASN1EncodableVector outerVec = new ASN1EncodableVector();
        outerVec.add(new ASN1Enumerated(0)); // success
        outerVec.add(responseBytes);
        return new DERSequence(outerVec).getEncoded();
    }

    /**
     * 校验请求 CertID 中的 issuerNameHash / issuerKeyHash 是否与颁发者证书一致
     * （P1-06：不同颁发者下相同序列号不得互相误命中）。
     *
     * <p>口径与响应构造完全一致：issuerKeyHash 取 SPKI BIT STRING 裸公钥字节，
     * issuerNameHash 取 issuer 证书 Subject 的规范 DER 编码。
     *
     * @param issuerCert  颁发者证书
     * @param hashAlgOid  请求 CertID 的哈希算法 OID
     * @param reqNameHash 请求中的 issuerNameHash
     * @param reqKeyHash  请求中的 issuerKeyHash
     * @return 一致返回 true；请求缺少哈希或计算失败返回 false
     */
    public static boolean matchesIssuerHash(X509Certificate issuerCert,
                                            String hashAlgOid,
                                            byte[] reqNameHash,
                                            byte[] reqKeyHash) {
        if (reqNameHash == null || reqKeyHash == null || hashAlgOid == null) {
            return false;
        }
        try {
            java.security.MessageDigest md =
                    java.security.MessageDigest.getInstance(hashDigestName(hashAlgOid));
            byte[] calcKeyHash = md.digest(
                    new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuerCert)
                            .getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
            md.reset();
            byte[] calcNameHash = md.digest(issuerCert.getSubjectX500Principal().getEncoded());
            return java.util.Arrays.equals(calcNameHash, reqNameHash)
                    && java.util.Arrays.equals(calcKeyHash, reqKeyHash);
        } catch (Exception e) {
            return false;
        }
    }

    /** 把哈希 OID 映射为 JCA 摘要名，用于回算 issuerNameHash/issuerKeyHash。 */
    private static String hashDigestName(String oid) {
        if (Sm2Util.OID_SM3.equals(oid)) {
            return "SM3";
        }
        switch (oid) {
            case "1.3.14.3.2.26":
                return "SHA-1";
            case "2.16.840.1.101.3.4.2.1":
                return "SHA-256";
            case "2.16.840.1.101.3.4.2.2":
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":
                return "SHA-512";
            case "2.16.840.1.101.3.4.2.7":
                return "SHA3-224";
            case "2.16.840.1.101.3.4.2.8":
                return "SHA3-256";
            case "2.16.840.1.101.3.4.2.9":
                return "SHA3-384";
            case "2.16.840.1.101.3.4.2.10":
                return "SHA3-512";
            default:
                // Unknown hash OID MUST fail loudly (audit: silently falling back to SHA-1
                // produces a wrong CertID that clients then reject as invalid signature).
                throw new IllegalArgumentException(
                        "unsupported OCSP CertID hash algorithm OID: " + oid);
        }
    }

    /**
     * 未授权错误响应：固定 5 字节 {0x30,0x03,0x0A,0x01,0x06}。
     */
    public static byte[] unauthorizedResponse() {
        return new byte[]{0x30, 0x03, 0x0A, 0x01, 0x06};
    }

    /**
     * malformedRequest 错误响应（RFC 6960 §4.2.1，status=1）：
     * {0x30,0x03,0x0A,0x01,0x01}。本服务只支持单证书请求，
     * 批量请求必须显式返回该状态，而不是静默只回答第一个 CertID。
     */
    public static byte[] malformedRequestResponse() {
        return new byte[]{0x30, 0x03, 0x0A, 0x01, 0x01};
    }

    /** OCSP 请求不被支持（批量 CertID 等）时抛出，调用方据此返回 malformedRequest。 */
    public static class UnsupportedRequestException extends Exception {
        private static final long serialVersionUID = 1L;

        public UnsupportedRequestException(String message) {
            super(message);
        }
    }
}
