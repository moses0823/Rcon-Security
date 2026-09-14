package tw.rconsecurity.auth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class NonceManager {
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Long> activeNonces = new ConcurrentHashMap<>();
    private final long lifetimeMillis;

    public NonceManager(long lifetimeMillis) {
        this.lifetimeMillis = lifetimeMillis;
    }

    public Challenge create(long serverTimeSeconds, long timeCounter) {
        cleanup(System.currentTimeMillis());
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        activeNonces.put(key(nonce), System.currentTimeMillis() + lifetimeMillis);
        return new Challenge(nonce, serverTimeSeconds, timeCounter);
    }

    public boolean consume(byte[] nonce) {
        Long expiresAt = activeNonces.remove(key(nonce));
        return expiresAt != null && expiresAt >= System.currentTimeMillis();
    }

    public int activeCount() {
        cleanup(System.currentTimeMillis());
        return activeNonces.size();
    }

    public void clear() {
        activeNonces.clear();
    }

    private void cleanup(long now) {
        activeNonces.entrySet().removeIf(entry -> entry.getValue() < now);
    }

    private String key(byte[] nonce) {
        return Base64.getEncoder().encodeToString(nonce);
    }

    public record Challenge(byte[] nonce, long serverTimeSeconds, long timeCounter) {
    }
}
