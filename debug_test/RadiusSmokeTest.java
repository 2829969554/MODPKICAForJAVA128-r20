package modpkica;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;

/**
 * RADIUS 整改冒烟测试（debug_test）：
 *   1) PAP 认证（无 EAP-Message → 不要求 Message-Authenticator）必须成功；
 *   2) EAP-MSCHAPv2（带 Message-Authenticator）必须成功；
 *   3) 计费包 Request Authenticator 校验：正确密钥有响应，错误密钥被丢弃（无响应）；
 *   4) EAP 请求缺失 Message-Authenticator 必须被拒绝（Access-Reject）。
 *
 * 报文按 RFC 2865/2866 手工构造，不依赖服务端内部类。
 * 运行：java -cp "out;BC185/*" modpkica.RadiusSmokeTest
 */
public class RadiusSmokeTest {

    static int pass = 0, fail = 0;

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
        if (ok) {
            pass++;
        } else {
            fail++;
        }
    }

    public static void main(String[] args) throws Exception {
        // 自带临时环境（args[0] 可指定目录），不依赖外部 PKI
        String base = args.length > 0 ? args[0]
                : System.getProperty("java.io.tmpdir") + "/modpkica_radius_smoke";
        new java.io.File(base, "PKI").mkdirs();
        Bc.init();
        UsersDB.ensureFile(base);
        // 用户名带时间戳：重复运行不因"用户名已存在"失败（add 对重名抛异常）
        String user = "smoke" + (System.currentTimeMillis() % 100000);
        UsersDB.add(base, user, "pass1234", "E", "users", "smoke");

        RadiusServer srv = new RadiusServer(base);
        srv.start(11812, 11813, "testsecret");
        Thread.sleep(300);
        try {
            Map<String, Object> r1 = srv.clientDial("PAP", user, "pass1234", "testsecret", 11812);
            check("PAP 认证成功（无 EAP-Message）", Boolean.TRUE.equals(r1.get("ok")));

            Map<String, Object> r2 = srv.clientDial("EAP-MSCHAPV2", user, "pass1234",
                    "testsecret", 11812);
            check("EAP-MSCHAPv2 认证成功（带 Message-Authenticator）",
                    Boolean.TRUE.equals(r2.get("ok")));

            check("计费请求（正确密钥）被接受", acctRoundTrip("testsecret", user));
            check("计费请求（错误密钥）被丢弃", !acctRoundTrip("wrongsecret", user));
            check("EAP 请求缺 Message-Authenticator 被拒绝（Access-Reject）",
                    eapWithoutMaRejected());
        } finally {
            srv.stop();
        }

        System.out.println("==========================================");
        System.out.println("  RADIUS RESULT: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    static void writeAttr(ByteArrayOutputStream out, int type, byte[] value) {
        out.write(type);
        out.write(value.length + 2);
        out.write(value, 0, value.length);
    }

    /** RFC 2866 §3 Acct-Request：Request Authenticator = MD5(包（该字段置 0）+ Secret)。 */
    static byte[] acctRequest(String secret, int id, String user) throws Exception {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        writeAttr(attrs, 40, new byte[]{0, 0, 0, 1});  // Acct-Status-Type = Start
        writeAttr(attrs, 1, user.getBytes(StandardCharsets.UTF_8));
        byte[] body = attrs.toByteArray();
        int len = 20 + body.length;
        byte[] pkt = new byte[len];
        pkt[0] = 4;                                     // Code = Accounting-Request
        pkt[1] = (byte) id;
        pkt[2] = (byte) (len >> 8);
        pkt[3] = (byte) len;
        System.arraycopy(body, 0, pkt, 20, body.length); // Authenticator 保持 16 个 0
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(pkt);
        md.update(secret.getBytes(StandardCharsets.UTF_8));
        System.arraycopy(md.digest(), 0, pkt, 4, 16);
        return pkt;
    }

    static boolean acctRoundTrip(String secret, String user) throws Exception {
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(1500);
            byte[] req = acctRequest(secret, 77, user);
            sock.send(new DatagramPacket(req, req.length,
                    InetAddress.getByName("127.0.0.1"), 11813));
            byte[] buf = new byte[4096];
            try {
                sock.receive(new DatagramPacket(buf, buf.length));
                return true;
            } catch (java.net.SocketTimeoutException e) {
                return false;
            }
        }
    }

    /** 带 EAP-Message 但不带 Message-Authenticator 的 Access-Request → 期望 Access-Reject(3)。 */
    static boolean eapWithoutMaRejected() throws Exception {
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(2000);
            ByteArrayOutputStream attrs = new ByteArrayOutputStream();
            writeAttr(attrs, 1, "eap-md5:alice".getBytes(StandardCharsets.UTF_8));
            writeAttr(attrs, 79, new byte[]{2, 9, 0, 5, 1});  // EAP Response/Identity
            byte[] body = attrs.toByteArray();
            int len = 20 + body.length;
            byte[] pkt = new byte[len];
            pkt[0] = 1;                                       // Code = Access-Request
            pkt[1] = 9;
            pkt[2] = (byte) (len >> 8);
            pkt[3] = (byte) len;
            new SecureRandom().nextBytes(new byte[0]);
            byte[] auth = new byte[16];
            new SecureRandom().nextBytes(auth);
            System.arraycopy(auth, 0, pkt, 4, 16);
            System.arraycopy(body, 0, pkt, 20, body.length);
            sock.send(new DatagramPacket(pkt, pkt.length,
                    InetAddress.getByName("127.0.0.1"), 11812));
            byte[] buf = new byte[4096];
            try {
                sock.receive(new DatagramPacket(buf, buf.length));
            } catch (java.net.SocketTimeoutException e) {
                return false;
            }
            return (buf[0] & 0xff) == 3;                      // CODE_ACCESS_REJECT
        }
    }
}
