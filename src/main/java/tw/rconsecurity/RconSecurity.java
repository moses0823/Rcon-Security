package tw.rconsecurity;

import org.bukkit.plugin.java.JavaPlugin;
import tw.rconsecurity.auth.AuthManager;
import tw.rconsecurity.auth.RateLimiter;
import tw.rconsecurity.command.RconSecurityCommand;
import tw.rconsecurity.config.ConfigManager;
import tw.rconsecurity.rcon.NativeRconClient;
import tw.rconsecurity.server.SecureRconServer;

import java.io.IOException;
import java.util.logging.Level;

public final class RconSecurity extends JavaPlugin {
    private ConfigManager configManager;
    private volatile RateLimiter rateLimiter;
    private volatile AuthManager authManager;
    private volatile SecureRconServer secureRconServer;

    @Override
    public void onEnable() {
        configManager = new ConfigManager(this);
        ConfigManager.Settings settings = configManager.load();
        RconSecurityCommand command = new RconSecurityCommand(this);
        if (getCommand("rconsecurity") != null) {
            getCommand("rconsecurity").setExecutor(command);
            getCommand("rconsecurity").setTabCompleter(command);
        }
        if (!settings.enabled()) {
            getLogger().info("Secure RCON Gateway is disabled by configuration.");
            return;
        }
        if (!startGateway(settings)) {
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        getLogger().info("RconSecurity enabled. Native RCON is not modified or intercepted.");
    }

    @Override
    public void onDisable() {
        SecureRconServer server = secureRconServer;
        if (server != null) {
            server.stop();
        }
        AuthManager auth = authManager;
        if (auth != null) {
            auth.clear();
        }
        rateLimiter = null;
        authManager = null;
        secureRconServer = null;
        getLogger().info("RconSecurity disabled.");
    }

    public synchronized boolean reloadSecurity() {
        SecureRconServer oldServer = secureRconServer;
        if (oldServer != null) {
            oldServer.stop();
        }
        AuthManager oldAuth = authManager;
        if (oldAuth != null) {
            oldAuth.clear();
        }
        secureRconServer = null;
        authManager = null;
        rateLimiter = null;
        ConfigManager.Settings settings = configManager.reload();
        if (!settings.enabled()) {
            secureRconServer = null;
            authManager = null;
            rateLimiter = null;
            return true;
        }
        return startGateway(settings);
    }

    public ConfigManager.Settings settings() {
        return configManager.getSettings();
    }

    public SecureRconServer gateway() {
        return secureRconServer;
    }

    public RateLimiter rateLimiter() {
        return rateLimiter;
    }

    public AuthManager authManager() {
        return authManager;
    }

    private boolean startGateway(ConfigManager.Settings settings) {
        RateLimiter newRateLimiter = new RateLimiter(settings.security());
        AuthManager newAuthManager = new AuthManager(settings, newRateLimiter);
        SecureRconServer newServer = new SecureRconServer(this, settings, newAuthManager, new NativeRconClient());
        try {
            if (settings.enabled()) {
                newServer.start();
            }
            rateLimiter = newRateLimiter;
            authManager = newAuthManager;
            secureRconServer = newServer;
            return true;
        } catch (IOException exception) {
            getLogger().log(Level.SEVERE, "Could not start Secure RCON Gateway", exception);
            newServer.stop();
            return false;
        }
    }
}
