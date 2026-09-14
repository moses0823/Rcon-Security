package tw.rconsecurity.protocol;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

public final class PacketReader {
    private PacketReader() {
    }

    public static Packet read(DataInputStream input, int maxPacketSize) throws IOException {
        int magic = input.readInt();
        if (magic != Protocol.MAGIC) {
            throw new ProtocolException("INVALID_MAGIC");
        }
        short version = input.readShort();
        if (version != Protocol.VERSION) {
            throw new ProtocolException("UNSUPPORTED_VERSION");
        }
        byte type = input.readByte();
        int length = input.readInt();
        if (length < 0 || length > maxPacketSize) {
            throw new ProtocolException("INVALID_PAYLOAD_LENGTH");
        }
        byte[] payload = new byte[length];
        input.readFully(payload);
        return new Packet(type, payload);
    }

    public static final class ProtocolException extends IOException {
        public ProtocolException(String message) {
            super(message);
        }
    }
}
