package tw.rconsecurity.auth;

import tw.rconsecurity.config.SecuritySettings;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class RateLimiter {
    private final SecuritySettings settings;
    private final Map<String, FailureState> failures = new ConcurrentHashMap<>();
    private final Map<String, Long> manualBlocks = new ConcurrentHashMap<>();

    public RateLimiter(SecuritySettings settings) {
        this.settings = settings;
    }

    public boolean isBlocked(String ip, String clientId) {
        long now = System.currentTimeMillis();
        Long manualExpiry = manualBlocks.get(ip);
        if (manualExpiry != null) {
            if (manualExpiry > now) {
                return true;
            }
            manualBlocks.remove(ip, manualExpiry);
        }
        return isFailureBlocked(ip, now) || isFailureBlocked(pairKey(ip, clientId), now);
    }

    public void recordFailure(String ip, String clientId) {
        long now = System.currentTimeMillis();
        recordFailure(ip, now);
        recordFailure(pairKey(ip, clientId), now);
    }

    public void recordSuccess(String ip, String clientId) {
        failures.remove(pairKey(ip, clientId));
        failures.remove(ip);
    }

    public void block(String ip) {
        manualBlocks.put(ip, System.currentTimeMillis() + settings.temporaryBlockSeconds() * 1000L);
    }

    public void unblock(String ip) {
        manualBlocks.remove(ip);
        failures.remove(ip);
    }

    public int blockedCount() {
        cleanup();
        return (int) manualBlocks.values().stream()
                .filter(expiry -> expiry > System.currentTimeMillis())
                .count();
    }

    public void clear() {
        failures.clear();
        manualBlocks.clear();
    }

    private void recordFailure(String key, long now) {
        failures.compute(key, (ignored, state) -> {
            if (state == null || now - state.windowStart > settings.authFailureWindowSeconds() * 1000L) {
                return new FailureState(now, 1, 0);
            }
            int attempts = state.attempts + 1;
            long blockedUntil = attempts >= settings.maxAuthAttempts()
                    ? Math.max(state.blockedUntil, now + settings.temporaryBlockSeconds() * 1000L)
                    : state.blockedUntil;
            return new FailureState(state.windowStart, attempts, blockedUntil);
        });
    }

    private boolean isFailureBlocked(String key, long now) {
        FailureState state = failures.get(key);
        if (state == null) {
            return false;
        }
        if (now - state.windowStart > settings.authFailureWindowSeconds() * 1000L) {
            failures.remove(key, state);
            return false;
        }
        return state.blockedUntil > now;
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        failures.entrySet().removeIf(entry -> now - entry.getValue().windowStart > settings.authFailureWindowSeconds() * 1000L
            && entry.getValue().blockedUntil <= now);
        manualBlocks.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    private String pairKey(String ip, String clientId) {
        return ip + "\u0000" + clientId;
    }

    private record FailureState(long windowStart, int attempts, long blockedUntil) {
    }
}
