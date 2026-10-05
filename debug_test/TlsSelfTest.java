import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import modpkica.PemIO;

import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.util.*;

/**
 * EAP-TLS 独立自测：BC TlsServerProtocol + TlsClientProtocol 直接 TCP 直连握手。
 * 若此处握手成功，则 RADIUS/EAP 分片传输层有问题；若失败，则 TLS 实现（签名/凭据）有问题。
 */
public class TlsSelfTest {

    static final class Cred {
        final BcTlsCrypto crypto;
        final AsymmetricKeyParameter key;
        final X509Certificate[] chain;
        Cred(BcTlsCrypto c, AsymmetricKeyParameter k, X509Certificate[] ch) { crypto = c; key = k; chain = ch; }
    }

    static final class MySigner implements TlsSigner {
        final BcTlsCrypto crypto;
        final AsymmetricKeyParameter key;
        MySigner(BcTlsCrypto c, AsymmetricKeyParameter k) { crypto = c; key = k; }
        public byte[] generateRawSignature(SignatureAndHashAlgorithm alg, byte[] hash) throws IOException {
            return generateRawSignature(alg, null, null, hash);
        }
        public byte[] generateRawSignature(SignatureAndHashAlgorithm alg, byte[] clientRandom, byte[] serverRandom, byte[] hash) throws IOException {
            try {
                if (key instanceof RSAKeyParameters) {
                    ASN1ObjectIdentifier oid;
                    switch (alg.getHash()) {
                        case HashAlgorithm.sha1: oid = new ASN1ObjectIdentifier("1.3.14.3.2.26"); break;
                        case HashAlgorithm.sha256: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); break;
                        case HashAlgorithm.sha384: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"); break;
                        case HashAlgorithm.sha512: oid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3"); break;
                        default: throw new IOException("hash " + alg.getHash());
                    }
                    byte[] di = new DERSequence(new ASN1Encodable[]{
                            new AlgorithmIdentifier(oid), new DEROctetString(hash)}).getEncoded();
                    RSAKeyParameters rsaKey = (RSAKeyParameters) key;
                    int modLen = (rsaKey.getModulus().bitLength() + 7) / 8;
                    byte[] em = new byte[modLen];
                    em[0] = 0x00; em[1] = 0x01;
                    int psLen = modLen - di.length - 3;
                    Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
                    em[2 + psLen] = 0x00;
                    System.arraycopy(di, 0, em, 3 + psLen, di.length);
                    RSAEngine eng = new RSAEngine();
                    eng.init(true, key);
                    return eng.processBlock(em, 0, em.length);
                }
                ECDSASigner s = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
                s.init(true, new ParametersWithRandom(key, new SecureRandom()));
                java.math.BigInteger[] rs = s.generateSignature(hash);
                return new DERSequence(new ASN1Encodable[]{
                        new ASN1Integer(rs[0]), new ASN1Integer(rs[1])}).getEncoded();
            } catch (IOException e) { throw e; } catch (Exception e) { throw new IOException(e); }
        }
        public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm alg) throws IOException { return null; }
    }

    static final class Svr extends AbstractTlsServer {
        final Cred cred;
        Svr(Cred c) { super(c.crypto); cred = c; }
        protected ProtocolVersion[] getSupportedVersions() { return new ProtocolVersion[]{ProtocolVersion.TLSv12}; }
        protected int[] getSupportedCipherSuites() {
            return new int[]{ CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 };
        }
        public TlsCredentials getCredentials() throws IOException {
            SignatureAndHashAlgorithm sig = cred.key instanceof RSAKeyParameters
                    ? new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa)
                    : new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
            TlsCryptoParameters cp = new TlsCryptoParameters(context);
            MySigner signer = new MySigner(cred.crypto, cred.key);
            TlsCertificate[] list = new TlsCertificate[cred.chain.length];
            for (int i = 0; i < cred.chain.length; i++) {
                try { list[i] = cred.crypto.createCertificate(cred.chain[i].getEncoded()); }
                catch (java.security.cert.CertificateEncodingException e) { throw new IOException(e); }
            }
            return new DefaultTlsCredentialedSigner(cp, signer, new Certificate(list), sig);
        }
        public CertificateRequest getCertificateRequest() throws IOException { return null; }
    }

    static final class Cli extends AbstractTlsClient {
        Cli(TlsCrypto c) { super(c); }
        protected ProtocolVersion[] getSupportedVersions() { return new ProtocolVersion[]{ProtocolVersion.TLSv12}; }
        protected int[] getSupportedCipherSuites() {
            return new int[]{ CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256 };
        }
        public TlsAuthentication getAuthentication() throws IOException {
            return new TlsAuthentication() {
                public void notifyServerCertificate(TlsServerCertificate c) throws IOException {}
                public TlsCredentials getClientCredentials(CertificateRequest r) throws IOException { return null; }
            };
        }
    }

    public static void main(String[] args) throws Exception {
        String dir = "PKI";
        X509Certificate cert = PemIO.readCert(dir + "/CA/25cef1995955a535fa2ab03204648f81.crt");
        AsymmetricKeyParameter key = PemIO.readPrivateKey(dir + "/CA/25cef1995955a535fa2ab03204648f81.key");
        System.out.println("cert subject=" + cert.getSubjectX500Principal()
                + " pubkey=" + cert.getPublicKey().getAlgorithm() + " " + cert.getPublicKey().getEncoded().length + "B");
        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        Cred cred = new Cred(crypto, key, new X509Certificate[]{cert});

        ServerSocket ss = new ServerSocket(18999);
        Thread st = new Thread(() -> {
            try {
                Socket c = ss.accept();
                TlsServerProtocol sp = new TlsServerProtocol(c.getInputStream(), c.getOutputStream());
                sp.accept(new Svr(cred));
                System.out.println("[SVR] 握手完成");
                byte[] msg = sp.getInputStream().readNBytes(4);
                System.out.println("[SVR] 收到应用数据: " + new String(msg));
                sp.getOutputStream().write(msg);
                sp.getOutputStream().flush();
                Thread.sleep(200);
                sp.close();
            } catch (Exception e) {
                System.out.println("[SVR] 异常: " + e);
                e.printStackTrace();
            }
        });
        st.start();

        Socket s = new Socket("127.0.0.1", 18999);
        TlsClientProtocol cp = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        cp.connect(new Cli(new BcTlsCrypto(new SecureRandom())));
        System.out.println("[CLI] 握手完成");
        cp.getOutputStream().write("ping".getBytes());
        cp.getOutputStream().flush();
        byte[] r = cp.getInputStream().readNBytes(4);
        System.out.println("[CLI] 收到回显: " + new String(r));
        cp.close();
        ss.close();
        System.out.println("RESULT=OK");
    }
}
