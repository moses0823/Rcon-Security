package tw.rconsecurity.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

public final class HmacAuthenticator {
    private HmacAuthenticator() {
    }

    public static boolean verify(String clientId, String secret, long timeCounter, byte[] nonce, byte[] providedHmac) {
        try {
            byte[] expected = calculate(clientId, secret, timeCounter, nonce);
            return MessageDigest.isEqual(expected, providedHmac);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            return false;
        }
    }

    private static byte[] calculate(String clientId, String secret, long timeCounter, byte[] nonce)
            throws GeneralSecurityException {
        byte[] secretBytes = Base64.getDecoder().decode(secret);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secretBytes, "HmacSHA256"));
        byte[] clientBytes = clientId.getBytes(StandardCharsets.UTF_8);
        ByteBuffer message = ByteBuffer.allocate(clientBytes.length + Long.BYTES + nonce.length);
        message.put(clientBytes).putLong(timeCounter).put(nonce);
        return mac.doFinal(message.array());
    }
}
