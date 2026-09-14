package tw.rconsecurity.protocol;

import java.nio.charset.StandardCharsets;

public final class Protocol {
    public static final int MAGIC = 0x52534543;
    public static final short VERSION = 1;
    public static final int HEADER_SIZE = Integer.BYTES + Short.BYTES + Byte.BYTES + Integer.BYTES;
    public static final byte HELLO = 1;
    public static final byte CHALLENGE = 2;
    public static final byte AUTH_RESPONSE = 3;
    public static final byte AUTH_RESULT = 4;
    public static final byte COMMAND = 5;
    public static final byte COMMAND_RESULT = 6;
    public static final byte ERROR = 7;

    private Protocol() {
    }

    public static byte[] encodeText(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static String decodeText(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static String truncateUtf8(String text, int maxBytes) {
        byte[] bytes = encodeText(text);
        if (bytes.length <= maxBytes) {
            return text;
        }
        int end = Math.max(0, maxBytes);
        while (end > 0 && (bytes[end] & 0xC0) == 0x80) {
            end--;
        }
        return new String(bytes, 0, end, StandardCharsets.UTF_8);
    }
}
