package tw.rconsecurity.config;

import org.bukkit.configuration.ConfigurationSection;
import tw.rconsecurity.RconSecurity;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ConfigManager {
    private static final int SECRET_BYTES = 32;
    private final RconSecurity plugin;
    private final SecureRandom secureRandom = new SecureRandom();
    private volatile Settings settings;

    public ConfigManager(RconSecurity plugin) {
        this.plugin = plugin;
    }

    public Settings load() {
        plugin.saveDefaultConfig();
        plugin.reloadConfig();
        ensureSecrets();
        settings = readSettings();
        return settings;
    }

    public Settings reload() {
        plugin.reloadConfig();
        ensureSecrets();
        settings = readSettings();
        return settings;
    }

    public Settings getSettings() {
        return settings;
    }

    private void ensureSecrets() {
        ConfigurationSection clients = plugin.getConfig().getConfigurationSection("clients");
        if (clients == null) {
            return;
        }
        boolean changed = false;
        for (String id : clients.getKeys(false)) {
            String path = "clients." + id + ".secret";
            String secret = plugin.getConfig().getString(path, "");
            if (secret.isBlank() || secret.equals("CHANGE-ME")) {
                plugin.getConfig().set(path, generateSecret());
                changed = true;
            }
        }
        if (changed) {
            plugin.saveConfig();
            plugin.getLogger().info("已為缺少 Secret 的 Client 產生 256-bit 隨機 Secret，請妥善保護設定檔。");
        }
    }

    private Settings readSettings() {
        int timeStep = positiveInt("time-step", 30);
        int drift = nonNegativeInt("allowed-clock-drift", 1);
        int protocolTimeout = positiveInt("protocol.handshake-timeout-ms", 5000);
        int securityTimeout = positiveInt("security.handshake-timeout-ms", protocolTimeout);
        Map<String, ClientCredential> clients = new LinkedHashMap<>();
        ConfigurationSection section = plugin.getConfig().getConfigurationSection("clients");
        if (section != null) {
            for (String id : section.getKeys(false)) {
                String secret = plugin.getConfig().getString("clients." + id + ".secret", "");
                clients.put(id, new ClientCredential(id,
                        plugin.getConfig().getBoolean("clients." + id + ".enabled", false), secret));
            }
        }
        SecuritySettings security = new SecuritySettings(
                positiveInt("security.max-auth-attempts", 5),
                positiveLong("security.auth-failure-window", 60),
                positiveLong("security.temporary-block-time", 300),
                positiveInt("security.max-connections", 32),
                securityTimeout);
        return new Settings(
                plugin.getConfig().getBoolean("secure-rcon.enabled", true),
                plugin.getConfig().getString("secure-rcon.host", "0.0.0.0"),
                positiveInt("secure-rcon.port", 25576),
                new ProtocolSettings(positiveInt("protocol.max-packet-size", 4096), protocolTimeout),
                timeStep,
                drift,
                security,
                Map.copyOf(clients),
                new NativeRconSettings(
                        plugin.getConfig().getString("native-rcon.host", "127.0.0.1"),
                        positiveInt("native-rcon.port", 25575),
                        plugin.getConfig().getString("native-rcon.password", "")),
                new LoggingSettings(
                        plugin.getConfig().getBoolean("logging.successful-auth", true),
                        plugin.getConfig().getBoolean("logging.failed-auth", true),
                        plugin.getConfig().getBoolean("logging.commands", false)));
    }

    private String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private int positiveInt(String path, int fallback) {
        return Math.max(1, plugin.getConfig().getInt(path, fallback));
    }

    private int nonNegativeInt(String path, int fallback) {
        return Math.max(0, plugin.getConfig().getInt(path, fallback));
    }

    private long positiveLong(String path, long fallback) {
        return Math.max(1, plugin.getConfig().getLong(path, fallback));
    }

    public record Settings(
            boolean enabled,
            String host,
            int port,
            ProtocolSettings protocol,
            int timeStepSeconds,
            int allowedClockDrift,
            SecuritySettings security,
            Map<String, ClientCredential> clients,
            NativeRconSettings nativeRcon,
            LoggingSettings logging) {
    }
}
