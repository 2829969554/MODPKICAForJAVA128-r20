package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * TimestampUtil —— RFC3161 时间戳与 Authenticode 时间戳。
 *
 * <p><b>RFC3161</b>：用 BC 的 TimeStampRequest / TimeStampResponse /
 * TimeStampTokenGenerator。Policy OID 固定 {@code 1.3.6.1.4.1.4146.1.95}
 * （不可用 2.23.140.1.3）。SerialNumber = 当前时间秒数；GenTime = now UTC；
 * 携带 TSA 证书链。SM2 TSA 时摘要与回传 hashAlgorithm 都用 SM3。
 *
 * <p><b>Authenticode</b>（/timestamp, /timestamp/sha1）：PKCS#7 分离签名格式，
 * 输入为 base64 内容，输出去掉 {@code -----BEGIN/END PKCS7-----} 标记的 PEM 正文。
 * digitype：1=sha1, 2=sha256, 3=sha384, 4=sha512；SM2 私钥时自动用 SM3。
 */
public final class TimestampUtil {

    /** 注册 BC Provider */
    static {
        Bc.init();
    }

    /** 本系统 TSA 策略 OID（不可用 2.23.140.1.3） */
    public static final ASN1ObjectIdentifier TSA_POLICY_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.4146.1.95");

    private TimestampUtil() {
    }

    /**
     * 解析后的 RFC3161 请求。
     */
    public static class Rfc3161Request {
        public String hashAlgOid;
        public byte[] messageImprint;
        public BigInteger nonce;
        public boolean certReq;
    }

    /**
     * 解析 DER 编码的 RFC3161 请求。
     */
    public static Rfc3161Request parseRfc3161Request(byte[] der) throws Exception {
        TimeStampRequest req = new TimeStampRequest(der);
        Rfc3161Request r = new Rfc3161Request();
        r.hashAlgOid = req.getMessageImprintAlgOID().getId();
        r.messageImprint = req.getMessageImprintDigest();
        r.nonce = req.getNonce();
        r.certReq = req.getCertReq();
        return r;
    }

    /**
     * 生成 RFC3161 时间戳响应（DER）。
     *
     * @param requestDer   原始请求 DER
     * @param tsaCert      TSA 证书
     * @param chain        TSA 证书链（可为空）
     * @param signer       ContentSigner（SM2 时用 SM2ContentSigner）
     * @param digestCalc   与请求 messageImprint 一致的摘要计算器（SM2 用 SM3）
     */
    public static byte[] createRfc3161Response(byte[] requestDer,
                                               X509Certificate tsaCert,
                                               List<X509Certificate> chain,
                                               ContentSigner signer,
                                               DigestCalculator digestCalc) throws Exception {
        TimeStampRequest req = new TimeStampRequest(requestDer);

        // SerialNumber = 160 位密码学安全随机正整数（秒级时间同秒多请求会碰撞）
        BigInteger serial = new BigInteger(160, new java.security.SecureRandom());
        if (serial.signum() <= 0) {
            serial = serial.negate();
        }
        Date genTime = new Date();

        // 由 ContentSigner 构造 SignerInfoGenerator（BC TSP 要求）
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        org.bouncycastle.cms.SignerInfoGenerator sigGen =
                new JcaSignerInfoGeneratorBuilder(dcp).build(signer, tsaCert);
        TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(
                sigGen, digestCalc, TSA_POLICY_OID);
        if (chain != null && !chain.isEmpty()) {
            tstGen.addCertificates(new JcaCertStore(chain));
        } else {
            tstGen.addCertificates(new JcaCertStore(Collections.singletonList(tsaCert)));
        }

        // 注意：BC 的 TimeStampResponseGenerator 各构造器中
        // 第二个 Set 参数恒为 acceptedAlgorithms（允许的摘要算法 OID），
        // 传 null 会拒绝所有请求（"no algorithms associated with request"）。
        java.util.Set<ASN1ObjectIdentifier> acceptedAlgs = new java.util.HashSet<>();
        acceptedAlgs.add(new ASN1ObjectIdentifier("1.3.14.3.2.26")); // SHA1
        acceptedAlgs.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")); // SHA256
        acceptedAlgs.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2")); // SHA384
        acceptedAlgs.add(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3")); // SHA512
        acceptedAlgs.add(new ASN1ObjectIdentifier(Sm2Util.OID_SM3)); // SM3
        TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(
                tstGen, acceptedAlgs, Collections.singleton(TSA_POLICY_OID));
        TimeStampResponse resp = respGen.generate(req, serial, genTime);
        return resp.getEncoded();
    }

    /**
     * 标准（RSA/ECC）RFC3161 响应便捷方法。
     */
    public static byte[] createRfc3161ResponseStandard(byte[] requestDer,
                                                       X509Certificate tsaCert,
                                                       List<X509Certificate> chain,
                                                       PrivateKey tsaKey,
                                                       String signatureAlgJca,
                                                       String digestAlgJca) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgJca).setProvider("BC").build(tsaKey);
        DigestCalculatorProvider prov = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        AlgorithmIdentifier digestAlgId = new TimeStampRequest(requestDer).getMessageImprintAlgID();
        DigestCalculator digestCalc = prov.get(digestAlgId);
        return createRfc3161Response(requestDer, tsaCert, chain, signer, digestCalc);
    }

    /**
     * SM2 TSA 用的 SM3 摘要计算器（BC 无内置 JCA SM3 DigestCalculator）。
     */
    public static class SM3DigestCalculator implements DigestCalculator {
        private final AlgorithmIdentifier algId;
        private final org.bouncycastle.crypto.digests.SM3Digest digest =
                new org.bouncycastle.crypto.digests.SM3Digest();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        public SM3DigestCalculator() {
            this.algId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(Sm2Util.OID_SM3));
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
        public byte[] getDigest() {
            byte[] data = buffer.toByteArray();
            // 取摘要后必须清空缓冲并复位摘要器：否则同一实例第二次调用会把
            // 上次数据 + 新数据一起哈希，产出错误的 messageImprint（客户端验签必失败）
            buffer.reset();
            digest.reset();
            digest.update(data, 0, data.length);
            byte[] out = new byte[digest.getDigestSize()];
            digest.doFinal(out, 0);
            return out;
        }
    }

    /**
     * Authenticode 时间戳：对内容做 PKCS#7 分离签名，输出 PEM 正文（无 BEGIN/END 标记）。
     *
     * <p>结构对齐 Go 生产版（cmd/main.go SignAndDetach）：
     * <ul>
     *   <li>eContent = 完整提取内容（不是摘要）；</li>
     *   <li>SignerInfo 的 signedAttrs 走标准属性（contentType=id-data、signingTime、
     *       messageDigest），并额外携带一个 {@code id-data(1.2.840.113549.1.7.1)}
     *       属性、值为完整内容——Authenticode 客户端校验必需；</li>
     *   <li>摘要算法由签名算法推导（SHA1/256/384/512、SM2→SM3）。</li>
     * </ul>
     *
     * @param content  提取后的被签名内容
     * @param cert     TSA 证书
     * @param key      TSA 私钥
     * @param digitype 1=sha1, 2=sha256, 3=sha384, 4=sha512；SM2 私钥自动用 SM3
     */
    public static byte[] createAuthenticodeTimestamp(byte[] content,
                                                      X509Certificate cert,
                                                      PrivateKey key,
                                                      int digitype) throws Exception {
        // BC 对 SM2 私钥报告的算法名是 "EC"，不能只看 key.getAlgorithm()：
        // 否则 SM2 TSA 会退化为 SHA256withECDSA（签名算法与密钥/证书不匹配）。
        boolean sm2 = "SM2".equalsIgnoreCase(key.getAlgorithm())
                || CertUtil.isSm2PublicKey(cert.getPublicKey());
        String signAlg;
        if (sm2) {
            signAlg = "SM3withSM2";
        } else {
            switch (digitype) {
                case 1:
                    signAlg = "SHA1with";
                    break;
                case 3:
                    signAlg = "SHA384with";
                    break;
                case 4:
                    signAlg = "SHA512with";
                    break;
                case 2:
                default:
                    signAlg = "SHA256with";
                    break;
            }
            signAlg += isEcc(key) ? "ECDSA" : "RSA";
        }

        ContentSigner signer = new JcaContentSignerBuilder(signAlg).setProvider("BC").build(key);
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        // 额外签名属性：id-data(1.2.840.113549.1.7.1) = 完整内容（对齐 Go 版 ExtraSignedAttributes）
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"),
                new DERSet(new DEROctetString(content))));
        AttributeTable extra = new AttributeTable(v);

        // signedAttrs = 标准属性(contentType/signingTime/messageDigest) + 上述额外属性
        SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder(dcp);
        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(extra));
        SignerInfoGenerator sigGen =
                builder.build(signer, new JcaX509CertificateHolder(cert));

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(sigGen);
        gen.addCertificates(new JcaCertStore(Collections.singletonList(cert)));

        // eContent = 完整内容，分离签名（detached）
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(content), true);
        byte[] der = signed.getEncoded();

        // 去掉 PEM BEGIN/END 标记：输出 base64 正文（与 Go 版一致）
        return Base64.encode(der);
    }

    /** 判断私钥是否为 ECC。 */
    private static boolean isEcc(PrivateKey key) {
        String a = key.getAlgorithm();
        return "EC".equalsIgnoreCase(a) || "ECDSA".equalsIgnoreCase(a) || "SM2".equalsIgnoreCase(a);
    }
}
