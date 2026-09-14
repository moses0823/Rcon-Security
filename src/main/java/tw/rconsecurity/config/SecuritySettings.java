package tw.rconsecurity.config;

public record SecuritySettings(
        int maxAuthAttempts,
        long authFailureWindowSeconds,
        long temporaryBlockSeconds,
        int maxConnections,
        int handshakeTimeoutMillis) {
}
