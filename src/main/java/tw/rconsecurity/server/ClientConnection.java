package tw.rconsecurity.server;

import tw.rconsecurity.RconSecurity;
import tw.rconsecurity.auth.AuthManager;
import tw.rconsecurity.config.ConfigManager;
import tw.rconsecurity.protocol.Packet;
import tw.rconsecurity.protocol.PacketReader;
import tw.rconsecurity.protocol.PacketWriter;
import tw.rconsecurity.protocol.Protocol;
import tw.rconsecurity.protocol.ProtocolCodec;
import tw.rconsecurity.rcon.NativeRconClient;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.logging.Level;

public final class ClientConnection implements Runnable {
    private final RconSecurity plugin;
    private final Socket socket;
    private final ConfigManager.Settings settings;
    private final AuthManager authManager;
    private final NativeRconClient nativeRconClient;

    public ClientConnection(RconSecurity plugin, Socket socket, ConfigManager.Settings settings,
                            AuthManager authManager, NativeRconClient nativeRconClient) {
        this.plugin = plugin;
        this.socket = socket;
        this.settings = settings;
        this.authManager = authManager;
        this.nativeRconClient = nativeRconClient;
    }

    @Override
    public void run() {
        String clientId = "unknown";
        String ip = socket.getInetAddress().getHostAddress();
        boolean authenticated = false;
        try (socket;
             DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            socket.setSoTimeout(settings.protocol().handshakeTimeoutMillis());
            Packet hello = PacketReader.read(input, settings.protocol().maxPacketSize());
            if (hello.type() != Protocol.HELLO) {
                sendError(output, "EXPECTED_HELLO");
                return;
            }
            clientId = ProtocolCodec.readHello(hello.payload());
            if (authManager.rateLimiter().isBlocked(ip, clientId)) {
                sendAuthResult(output, false, "TEMPORARILY_BLOCKED");
                logFailure(clientId, ip, "TEMPORARILY_BLOCKED");
                return;
            }
            if (!authManager.isClientAvailable(clientId)) {
                sendAuthResult(output, false, "UNKNOWN_OR_DISABLED_CLIENT");
                authManager.reject(ip, clientId);
                logFailure(clientId, ip, "UNKNOWN_OR_DISABLED_CLIENT");
                return;
            }

            ProtocolCodec.Challenge challenge = authManager.createChallenge();
            PacketWriter.write(output, Protocol.CHALLENGE,
                    ProtocolCodec.challenge(challenge.nonce(), challenge.serverTimeSeconds(), challenge.timeCounter()),
                    settings.protocol().maxPacketSize());
            Packet response = PacketReader.read(input, settings.protocol().maxPacketSize());
            if (response.type() != Protocol.AUTH_RESPONSE) {
                sendAuthResult(output, false, "EXPECTED_AUTH_RESPONSE");
                logFailure(clientId, ip, "EXPECTED_AUTH_RESPONSE");
                return;
            }
            ProtocolCodec.AuthResponse authResponse = ProtocolCodec.readAuthResponse(response.payload());
            AuthManager.AuthResult authResult = authManager.authenticate(
                    ip, clientId, challenge, authResponse.nonce(), authResponse.hmac());
            sendAuthResult(output, authResult.success(), authResult.reason());
            if (!authResult.success()) {
                logFailure(clientId, ip, authResult.reason());
                return;
            }
            authenticated = true;
            logSuccess(clientId, ip);
            handleCommands(input, output, clientId, ip);
        } catch (java.net.SocketTimeoutException exception) {
            if (!authenticated) {
                logFailure(clientId, ip, "TIMEOUT");
            }
        } catch (IOException exception) {
            if (settings.logging().failedAuth()) {
                plugin.getLogger().log(Level.FINE, "Secure connection closed: client=" + safe(clientId)
                        + " ip=" + ip + " reason=" + safe(exception.getMessage()));
            }
        } catch (RuntimeException exception) {
            plugin.getLogger().log(Level.WARNING, "Unexpected secure RCON connection error", exception);
        }
    }

    private void handleCommands(DataInputStream input, DataOutputStream output, String clientId, String ip)
            throws IOException {
        while (!socket.isClosed()) {
            Packet packet = PacketReader.read(input, settings.protocol().maxPacketSize());
            if (packet.type() != Protocol.COMMAND) {
                sendError(output, "EXPECTED_COMMAND");
                return;
            }
            String command = ProtocolCodec.readCommand(packet.payload());
            if (settings.logging().commands()) {
                plugin.getLogger().info("Command forwarded: client=" + safe(clientId) + " ip=" + ip
                        + " command=" + safe(command));
            }
            try {
                String result = nativeRconClient.execute(command, settings.nativeRcon(),
                        settings.protocol().handshakeTimeoutMillis());
                PacketWriter.write(output, Protocol.COMMAND_RESULT,
                        ProtocolCodec.commandResult(true, result, settings.protocol().maxPacketSize()),
                        settings.protocol().maxPacketSize());
            } catch (IOException exception) {
                PacketWriter.write(output, Protocol.COMMAND_RESULT,
                        ProtocolCodec.commandResult(false, "NATIVE_RCON_ERROR", settings.protocol().maxPacketSize()),
                        settings.protocol().maxPacketSize());
                plugin.getLogger().log(Level.WARNING, "Native RCON command failed: client=" + safe(clientId)
                        + " ip=" + ip, exception);
            }
        }
    }

    private void sendAuthResult(DataOutputStream output, boolean success, String reason) throws IOException {
        PacketWriter.write(output, Protocol.AUTH_RESULT,
                ProtocolCodec.authResult(success, reason, settings.protocol().maxPacketSize()),
                settings.protocol().maxPacketSize());
    }

    private void sendError(DataOutputStream output, String reason) throws IOException {
        sendAuthResult(output, false, reason);
    }

    private void logSuccess(String clientId, String ip) {
        if (settings.logging().successfulAuth()) {
            plugin.getLogger().info("Authentication successful: client=" + safe(clientId) + " ip=" + ip);
        }
    }

    private void logFailure(String clientId, String ip, String reason) {
        if (settings.logging().failedAuth()) {
            plugin.getLogger().warning("Authentication failed: client=" + safe(clientId) + " ip=" + ip
                    + " reason=" + safe(reason));
        }
    }

    private String safe(String value) {
        return value == null ? "unknown" : value.replaceAll("[\\r\\n\\t]", "_");
    }
}
