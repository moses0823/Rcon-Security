package tw.rconsecurity.protocol;

import java.io.DataOutputStream;
import java.io.IOException;

public final class PacketWriter {
    private PacketWriter() {
    }

    public static void write(DataOutputStream output, byte type, byte[] payload, int maxPacketSize) throws IOException {
        if (payload.length > maxPacketSize) {
            throw new IOException("Payload exceeds configured maximum");
        }
        output.writeInt(Protocol.MAGIC);
        output.writeShort(Protocol.VERSION);
        output.writeByte(type);
        output.writeInt(payload.length);
        output.write(payload);
        output.flush();
    }
}
