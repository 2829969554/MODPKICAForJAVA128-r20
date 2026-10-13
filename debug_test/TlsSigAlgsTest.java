import org.bouncycastle.tls.*;
import java.util.*;
import java.io.*;

/** 独立验证 BC 1.85 的 supportedSignatureAlgorithms 编码。 */
public class TlsSigAlgsTest {
    public static void main(String[] args) throws Exception {
        Vector<SignatureAndHashAlgorithm> v = new Vector<>();
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa_pss_rsae_sha256));
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha384, SignatureAlgorithm.rsa_pss_rsae_sha384));
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha512, SignatureAlgorithm.rsa_pss_rsae_sha512));
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha384, SignatureAlgorithm.ecdsa));
        v.add(new SignatureAndHashAlgorithm(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa));
        System.out.println("size=" + v.size());
        for (SignatureAndHashAlgorithm a : v) {
            System.out.println("  hash=" + a.getHash() + " sig=" + a.getSignature()
                    + " recognized=" + SignatureAlgorithm.isRecognized(a.getSignature()));
        }
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try {
            TlsUtils.encodeSupportedSignatureAlgorithms(v, b);
            System.out.println("encode OK len=" + b.size());
        } catch (Exception e) {
            System.out.println("encode FAIL: " + e);
            e.printStackTrace(System.out);
        }
        Hashtable exts = new Hashtable();
        try {
            TlsExtensionsUtils.addSignatureAlgorithmsExtension(exts, v);
            System.out.println("addSignatureAlgorithmsExtension OK ext.size=" + exts.size());
        } catch (Exception e) {
            System.out.println("addExtension FAIL: " + e);
            e.printStackTrace(System.out);
        }
    }
}
