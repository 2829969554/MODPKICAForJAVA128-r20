package modpkica;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

/**
 * OCSP 整改冒烟测试（debug_test）：
 *   单 CertID 请求正常解析；多 CertID 批量请求抛 UnsupportedRequestException（调用方回 malformedRequest）。
 *
 * 运行：java -cp "out;BC185/*" modpkica.OcspSmokeTest
 */
public class OcspSmokeTest {

    static int pass = 0, fail = 0;

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
        if (ok) {
            pass++;
        } else {
            fail++;
        }
    }

    /** SHA-1 DigestCalculator（BC 已移除 JCA 反射版，须手工实现）。 */
    static class Sha1Calc implements DigestCalculator {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private final AlgorithmIdentifier alg =
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"), DERNull.INSTANCE);

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return alg;
        }

        public java.io.OutputStream getOutputStream() {
            return buf;
        }

        public byte[] getDigest() {
            try {
                byte[] out = MessageDigest.getInstance("SHA-1").digest(buf.toByteArray());
                buf.reset();
                return out;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // 自带临时环境（args[0] 可指定目录）：无根证书时现场生成一个
        String base = args.length > 0 ? args[0]
                : System.getProperty("java.io.tmpdir") + "/modpkica_ocsp_smoke";
        new java.io.File(base, "PKI").mkdirs();
        Bc.init();
        CertsDB db = new CertsDB();
        db.load(base);
        if (db.getAll().isEmpty()) {
            MakeRoot.run(base, new String[]{"CN=OCSP Smoke Root,O=Test,C=CN", "2048", "sha256", "RSA"});
            db.load(base);
        }
        db.load(base);
        // 用 scratch 环境中的根证书作为颁发者构造 CertID
        String rootSerial = null;
        for (CertsDB.CertEntry e : db.getAll()) {
            if (e.type == 'R') {
                rootSerial = e.serial;
                break;
            }
        }
        if (rootSerial == null) {
            throw new IllegalStateException("scratch PKI 无根证书，跳过");
        }
        X509Certificate root = PemIO.readCert(base + "/PKI/ROOT/" + rootSerial + ".crt");
        DigestCalculator dc = new Sha1Calc();
        CertificateID cid1 = new CertificateID(dc, new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(root),
                new BigInteger("0102030405", 16));
        CertificateID cid2 = new CertificateID(dc, new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(root),
                new BigInteger("0a0b0c0d0e", 16));

        // 单 CertID
        OCSPReqBuilder b1 = new OCSPReqBuilder();
        b1.addRequest(cid1);
        b1.setRequestExtensions(new Extensions(new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new byte[]{0x04, 0x02, 0x01, 0x02})));
        OcspUtil.OcspRequest parsed = OcspUtil.parseRequest(b1.build().getEncoded());
        check("单 CertID 请求解析成功", parsed.serialNumber.equals(new BigInteger("0102030405", 16)));

        // 多 CertID
        OCSPReqBuilder b2 = new OCSPReqBuilder();
        b2.addRequest(cid1);
        b2.addRequest(cid2);
        boolean threw = false;
        try {
            OcspUtil.parseRequest(b2.build().getEncoded());
        } catch (OcspUtil.UnsupportedRequestException e) {
            threw = true;
            System.out.println("        拒绝原因: " + e.getMessage());
        }
        check("多 CertID 请求被显式拒绝（UnsupportedRequestException）", threw);
        check("malformedRequest 响应字节正确（30 03 0A 01 01）",
                java.util.Arrays.equals(OcspUtil.malformedRequestResponse(),
                        new byte[]{0x30, 0x03, 0x0A, 0x01, 0x01}));

        System.out.println("==========================================");
        System.out.println("  OCSP RESULT: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
