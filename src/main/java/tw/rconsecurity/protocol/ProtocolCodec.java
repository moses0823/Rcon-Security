package tw.rconsecurity.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public final class ProtocolCodec {
    private ProtocolCodec() {
    }

    public static byte[] hello(String clientId) throws IOException {
        return utf8Field(clientId, 256);
    }

    public static String readHello(byte[] payload) throws IOException {
        return readUtf8Field(payload, 256);
    }

    public static byte[] challenge(byte[] nonce, long serverTimeSeconds, long timeCounter) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeShort(nonce.length);
        output.write(nonce);
        output.writeLong(serverTimeSeconds);
        output.writeLong(timeCounter);
        return bytes.toByteArray();
    }

    public static Challenge readChallenge(byte[] payload) throws IOException {
        ByteBuffer input = ByteBuffer.wrap(payload);
        if (payload.length < Short.BYTES + Long.BYTES * 2) {
            throw new IOException("MALFORMED_CHALLENGE");
        }
        int nonceLength = Short.toUnsignedInt(input.getShort());
        if (nonceLength < 16 || nonceLength > 64 || input.remaining() != nonceLength + Long.BYTES * 2) {
            throw new IOException("MALFORMED_CHALLENGE");
        }
        byte[] nonce = new byte[nonceLength];
        input.get(nonce);
        return new Challenge(nonce, input.getLong(), input.getLong());
    }

    public static byte[] authResponse(byte[] nonce, byte[] hmac) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeShort(nonce.length);
        output.write(nonce);
        output.writeShort(hmac.length);
        output.write(hmac);
        return bytes.toByteArray();
    }

    public static AuthResponse readAuthResponse(byte[] payload) throws IOException {
        ByteBuffer input = ByteBuffer.wrap(payload);
        if (payload.length < Short.BYTES * 2) {
            throw new IOException("MALFORMED_AUTH_RESPONSE");
        }
        int nonceLength = Short.toUnsignedInt(input.getShort());
        if (nonceLength < 16 || nonceLength > 64 || input.remaining() < nonceLength + Short.BYTES) {
            throw new IOException("MALFORMED_AUTH_RESPONSE");
        }
        byte[] nonce = new byte[nonceLength];
        input.get(nonce);
        int hmacLength = Short.toUnsignedInt(input.getShort());
        if (hmacLength != 32 || input.remaining() != hmacLength) {
            throw new IOException("MALFORMED_AUTH_RESPONSE");
        }
        byte[] hmac = new byte[hmacLength];
        input.get(hmac);
        return new AuthResponse(nonce, hmac);
    }

    public static byte[] authResult(boolean success, String reason, int maxPacketSize) {
        byte[] reasonBytes = reason.getBytes(StandardCharsets.UTF_8);
        int maxReasonBytes = Math.max(0, maxPacketSize - 3);
        if (reasonBytes.length > maxReasonBytes) {
            reason = Protocol.truncateUtf8(reason, maxReasonBytes);
            reasonBytes = reason.getBytes(StandardCharsets.UTF_8);
        }
        ByteBuffer result = ByteBuffer.allocate(1 + Short.BYTES + reasonBytes.length);
        result.put((byte) (success ? 1 : 0));
        result.putShort((short) reasonBytes.length);
        result.put(reasonBytes);
        return result.array();
    }

    public static AuthResult readAuthResult(byte[] payload) throws IOException {
        if (payload.length < 3) {
            throw new IOException("MALFORMED_AUTH_RESULT");
        }
        ByteBuffer input = ByteBuffer.wrap(payload);
        boolean success = input.get() != 0;
        int reasonLength = Short.toUnsignedInt(input.getShort());
        if (reasonLength != input.remaining()) {
            throw new IOException("MALFORMED_AUTH_RESULT");
        }
        byte[] reason = new byte[reasonLength];
        input.get(reason);
        return new AuthResult(success, new String(reason, StandardCharsets.UTF_8));
    }

    public static byte[] command(String command) {
        return command.getBytes(StandardCharsets.UTF_8);
    }

    public static String readCommand(byte[] payload) throws IOException {
        if (payload.length == 0) {
            throw new IOException("EMPTY_COMMAND");
        }
        return new String(payload, StandardCharsets.UTF_8);
    }

    public static byte[] commandResult(boolean success, String result, int maxPacketSize) {
        int maxTextBytes = Math.max(0, maxPacketSize - 3);
        String safeResult = Protocol.truncateUtf8(result, maxTextBytes);
        byte[] text = safeResult.getBytes(StandardCharsets.UTF_8);
        ByteBuffer payload = ByteBuffer.allocate(1 + Short.BYTES + text.length);
        payload.put((byte) (success ? 1 : 0));
        payload.putShort((short) text.length);
        payload.put(text);
        return payload.array();
    }

    public static CommandResult readCommandResult(byte[] payload) throws IOException {
        if (payload.length < 3) {
            throw new IOException("MALFORMED_COMMAND_RESULT");
        }
        ByteBuffer input = ByteBuffer.wrap(payload);
        boolean success = input.get() != 0;
        int textLength = Short.toUnsignedInt(input.getShort());
        if (textLength != input.remaining()) {
            throw new IOException("MALFORMED_COMMAND_RESULT");
        }
        byte[] text = new byte[textLength];
        input.get(text);
        return new CommandResult(success, new String(text, StandardCharsets.UTF_8));
    }

    private static byte[] utf8Field(String value, int maxBytes) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > maxBytes) {
            throw new IOException("INVALID_TEXT_LENGTH");
        }
        ByteBuffer payload = ByteBuffer.allocate(Short.BYTES + bytes.length);
        payload.putShort((short) bytes.length).put(bytes);
        return payload.array();
    }

    private static String readUtf8Field(byte[] payload, int maxBytes) throws IOException {
        if (payload.length < Short.BYTES) {
            throw new IOException("MALFORMED_TEXT_FIELD");
        }
        ByteBuffer input = ByteBuffer.wrap(payload);
        int length = Short.toUnsignedInt(input.getShort());
        if (length == 0 || length > maxBytes || input.remaining() != length) {
            throw new IOException("MALFORMED_TEXT_FIELD");
        }
        byte[] text = new byte[length];
        input.get(text);
        return new String(text, StandardCharsets.UTF_8);
    }

    public record Challenge(byte[] nonce, long serverTimeSeconds, long timeCounter) {
    }

    public record AuthResponse(byte[] nonce, byte[] hmac) {
    }

    public record AuthResult(boolean success, String reason) {
    }

    public record CommandResult(boolean success, String result) {
    }
}
