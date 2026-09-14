package tw.rconsecurity.rcon;

import tw.rconsecurity.config.NativeRconSettings;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public final class NativeRconClient {
    private static final int AUTH_TYPE = 3;
    private static final int COMMAND_TYPE = 2;
    private static final int RESPONSE_VALUE_TYPE = 0;
    private static final int AUTH_RESPONSE_TYPE = 2;
    private static final int MAX_NATIVE_PACKET_SIZE = 1_048_576;
    private static final AtomicInteger REQUEST_IDS = new AtomicInteger(1);

    public String execute(String command, NativeRconSettings settings, int timeoutMillis) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(settings.host(), settings.port()), timeoutMillis);
            socket.setSoTimeout(timeoutMillis);
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            int authId = nextRequestId();
            writePacket(output, authId, AUTH_TYPE, settings.password());
            RconPacket authResponse = readPacket(input);
            if (authResponse.id() == -1 || authResponse.type() != AUTH_RESPONSE_TYPE) {
                throw new IOException("NATIVE_RCON_AUTH_FAILED");
            }

            int commandId = nextRequestId();
            writePacket(output, commandId, COMMAND_TYPE, command);
            StringBuilder result = new StringBuilder();
            RconPacket response = readPacket(input);
            if (response.id() != commandId || response.type() != RESPONSE_VALUE_TYPE) {
                throw new IOException("NATIVE_RCON_INVALID_RESPONSE");
            }
            result.append(response.body());
            socket.setSoTimeout(Math.min(timeoutMillis, 150));
            while (true) {
                try {
                    RconPacket additional = readPacket(input);
                    if (additional.id() != commandId || additional.type() != RESPONSE_VALUE_TYPE) {
                        break;
                    }
                    result.append(additional.body());
                } catch (java.net.SocketTimeoutException ignored) {
                    break;
                }
            }
            return result.toString();
        }
    }

    private static void writePacket(DataOutputStream output, int id, int type, String body) throws IOException {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        int length = Integer.BYTES + Integer.BYTES + bodyBytes.length + 2;
        ByteBuffer packet = ByteBuffer.allocate(Integer.BYTES + length).order(ByteOrder.LITTLE_ENDIAN);
        packet.putInt(length).putInt(id).putInt(type).put(bodyBytes).put((byte) 0).put((byte) 0);
        output.write(packet.array());
        output.flush();
    }

    private static RconPacket readPacket(DataInputStream input) throws IOException {
        int length;
        try {
            length = Integer.reverseBytes(input.readInt());
        } catch (EOFException exception) {
            throw new IOException("NATIVE_RCON_CONNECTION_CLOSED", exception);
        }
        if (length < 10 || length > MAX_NATIVE_PACKET_SIZE) {
            throw new IOException("NATIVE_RCON_INVALID_PACKET_LENGTH");
        }
        byte[] packet = new byte[length];
        input.readFully(packet);
        ByteBuffer data = ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN);
        int id = data.getInt();
        int type = data.getInt();
        int bodyLength = length - Integer.BYTES - Integer.BYTES - 2;
        byte[] body = new byte[bodyLength];
        data.get(body);
        return new RconPacket(id, type, new String(body, StandardCharsets.UTF_8));
    }

    private static int nextRequestId() {
        int id = REQUEST_IDS.getAndIncrement();
        return id == -1 ? REQUEST_IDS.getAndIncrement() : id;
    }

    private record RconPacket(int id, int type, String body) {
    }
}
