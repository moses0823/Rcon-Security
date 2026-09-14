package tw.rconsecurity.config;

public record ProtocolSettings(int maxPacketSize, int handshakeTimeoutMillis) {
}
