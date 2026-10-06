// RFC 2759 §9.2 Hash Example 验证 MS-CHAPv2 AuthenticatorResponse（与 RadiusServer.buildMschapv2Success 同公式）
import org.bouncycastle.crypto.digests.MD4Digest;
import java.security.MessageDigest;
import java.util.Arrays;

public class Rfc2759Check {
    static byte[] md4(byte[] in) {
        MD4Digest d = new MD4Digest();
        d.update(in, 0, in.length);
        byte[] out = new byte[16];
        d.doFinal(out, 0);
        return out;
    }
    static byte[] sha1(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }
    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    public static void main(String[] args) throws Exception {
        String user = "User";
        String password = "clientPass";
        byte[] authChallenge = hex("5B5D7C7D7B3F2F3E3C2C602132262628");
        byte[] peerChallenge = hex("21402324255E262A28295F2B3A337C7E");
        byte[] ntResponse = hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        byte[] pwHash = md4(password.getBytes("UTF-16LE"));
        byte[] pwHashHash = md4(pwHash);
        byte[] challengeHash = Arrays.copyOf(sha1(peerChallenge, authChallenge, user.getBytes("US-ASCII")), 8);
        byte[] magic1 = "Magic server to client signing constant".getBytes("US-ASCII");
        byte[] magic2 = "Pad to make it more than one iteration".getBytes("US-ASCII");
        byte[] digest1 = sha1(pwHashHash, ntResponse, magic1);
        byte[] digest2 = sha1(digest1, challengeHash, magic2);
        System.out.println("NT-Hash      : " + toHex(pwHash) + "  预期 44EBBA8D5312B8D611474411F56989AE");
        System.out.println("NT-Hash-Hash : " + toHex(pwHashHash) + "  预期 41C00C584BD2D91C4017A2A12FA59F3F");
        System.out.println("Challenge    : " + toHex(challengeHash) + "  预期 D02E4386BCE91226");
        String got = "S=" + toHex(digest2).toUpperCase();
        String exp = "S=407A5589115FD0D6209F510FE9C04566932CDA56";
        System.out.println("AuthResponse : " + got);
        System.out.println("预期         : " + exp);
        System.out.println("结果         : " + (got.equals(exp) ? "PASS - 公式 100% 正确" : "FAIL"));
    }
}
