import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

/**
 * 纯 BC 最小复现：把 strongSwan 手机原始 ClientHello（216B TLS 数据，含
 * 0x000d 签名算法扩展 + 0x0032 异常 ALPN 扩展）直接喂给与 ModpkicaTlsServer
 * 相同配置的 BC 服务器，定位 handshake_failure(40) 具体协商失败点。
 */
public class DebugTlsServer {
    static byte[] hexToBytes(String s) {
        s = s.replaceAll("\\s", ""); byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    public static void main(String[] args) throws Exception {
        // 手机 TLS 数据（剥离 EAP 头后的 216B 原始 ClientHello）
        byte[] hello = hexToBytes(
                "16030300d3010000cf03036aca475423be48c6942a2b0cfc56053db8ddb51cdd2d5593523807c256a0d645"
                + "000048c02cc024c00ac02bc023c009c030c028c014c02fc027c013009f006b003900c40088009e0067003300be0045009d003d0035009c003c002f00c0008400ba0041c006c010003b"
                + "00020100005e"
                + "000a0010000e00170018001900150013001d001e"
                + "000b00020100"
                + "000d001e001c040305030603080708080804080508060809080a080b040105010601"
                + "0032001e001c040305030603080708080804080508060809080a080b040105010601");
        System.out.println("手机 ClientHello " + hello.length + "B");

        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
        ByteArrayInputStream in = new ByteArrayInputStream(hello);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsServerProtocol proto = new TlsServerProtocol(in, out);

        AbstractTlsServer server = new AbstractTlsServer(crypto) {
            @Override protected ProtocolVersion[] getSupportedVersions() {
                return new ProtocolVersion[]{ProtocolVersion.TLSv12};
            }
            @Override public boolean shouldUseExtendedMasterSecret() { return false; }
            @Override public void notifySecureRenegotiation(boolean secureNegotiation) {
                // EAP-TLS 单会话无重协商：不强求 RFC 5746 renegotiation_info(0xff01)
                // strongSwan/OpenSSL 客户端不发该扩展，默认实现会抛 handshake_failure(40)
            }
            @Override protected int[] getSupportedCipherSuites() {
                return new int[]{
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256};
            }
            @Override public TlsCredentials getCredentials() throws IOException {
                throw new IOException("SERVER:getCredentials 被调用（说明 ClientHello 协商已通过）");
            }
        };

        try {
            proto.accept(server);
            System.out.println("accept 返回（异常）: out=" + out.size() + "B");
            System.out.println("服务端输出: " + hex(out.toByteArray(), 256));
        } catch (TlsFatalAlert fa) {
            System.out.println("TlsFatalAlert=alert(" + fa.getAlertDescription() + ")");
            for (StackTraceElement ste : fa.getStackTrace()) System.out.println("    at " + ste);
        } catch (Exception e) {
            System.out.println("异常: " + e);
            for (StackTraceElement ste : e.getStackTrace()) System.out.println("    at " + ste);
        }
    }

    static String hex(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length && i < max; i++) sb.append(String.format("%02x", b[i] & 0xff));
        if (b.length > max) sb.append("...(+").append(b.length - max).append("B)");
        return sb.toString();
    }
}
