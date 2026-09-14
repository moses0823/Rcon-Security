package tw.rconsecurity.auth;

import tw.rconsecurity.config.ClientCredential;
import tw.rconsecurity.config.ConfigManager;
import tw.rconsecurity.protocol.ProtocolCodec;

public final class AuthManager {
    private final ConfigManager.Settings settings;
    private final NonceManager nonceManager;
    private final RateLimiter rateLimiter;

    public AuthManager(ConfigManager.Settings settings, RateLimiter rateLimiter) {
        this.settings = settings;
        this.rateLimiter = rateLimiter;
        this.nonceManager = new NonceManager(settings.protocol().handshakeTimeoutMillis());
    }

    public boolean isClientAvailable(String clientId) {
        ClientCredential credential = settings.clients().get(clientId);
        return credential != null && credential.enabled() && !credential.secret().isBlank();
    }

    public ProtocolCodec.Challenge createChallenge() {
        long now = System.currentTimeMillis() / 1000L;
        long counter = Math.floorDiv(now, settings.timeStepSeconds());
        NonceManager.Challenge challenge = nonceManager.create(now, counter);
        return new ProtocolCodec.Challenge(challenge.nonce(), challenge.serverTimeSeconds(), challenge.timeCounter());
    }

    public AuthResult authenticate(String ip, String clientId, ProtocolCodec.Challenge challenge,
                                   byte[] nonce, byte[] hmac) {
        if (rateLimiter.isBlocked(ip, clientId)) {
            return new AuthResult(false, "TEMPORARILY_BLOCKED");
        }
        ClientCredential credential = settings.clients().get(clientId);
        if (credential == null) {
            return failure(ip, clientId, "UNKNOWN_CLIENT");
        }
        if (!credential.enabled()) {
            return failure(ip, clientId, "CLIENT_DISABLED");
        }
        long now = System.currentTimeMillis() / 1000L;
        long currentCounter = Math.floorDiv(now, settings.timeStepSeconds());
        if (Math.abs(currentCounter - challenge.timeCounter()) > settings.allowedClockDrift()) {
            return failure(ip, clientId, "TIMESTAMP_OUT_OF_RANGE");
        }
        if (!java.util.Arrays.equals(challenge.nonce(), nonce)) {
            return failure(ip, clientId, "INVALID_NONCE");
        }
        if (!HmacAuthenticator.verify(clientId, credential.secret(), challenge.timeCounter(), nonce, hmac)) {
            return failure(ip, clientId, "INVALID_HMAC");
        }
        if (!nonceManager.consume(nonce)) {
            return failure(ip, clientId, "NONCE_ALREADY_USED");
        }
        rateLimiter.recordSuccess(ip, clientId);
        return new AuthResult(true, "SUCCESS");
    }

    public RateLimiter rateLimiter() {
        return rateLimiter;
    }

    public void reject(String ip, String clientId) {
        rateLimiter.recordFailure(ip, clientId);
    }

    public int activeNonceCount() {
        return nonceManager.activeCount();
    }

    public void clear() {
        nonceManager.clear();
        rateLimiter.clear();
    }

    private AuthResult failure(String ip, String clientId, String reason) {
        rateLimiter.recordFailure(ip, clientId);
        return new AuthResult(false, reason);
    }

    public record AuthResult(boolean success, String reason) {
    }
}
