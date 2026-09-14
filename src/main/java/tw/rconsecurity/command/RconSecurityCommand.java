package tw.rconsecurity.command;

import net.kyori.adventure.text.Component;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import tw.rconsecurity.RconSecurity;
import tw.rconsecurity.config.ClientCredential;

import java.util.ArrayList;
import java.util.List;

public final class RconSecurityCommand implements CommandExecutor, TabCompleter {
    private static final String PERMISSION = "rconsecurity.admin";
    private final RconSecurity plugin;

    public RconSecurityCommand(RconSecurity plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission(PERMISSION)) {
            sender.sendMessage(Component.text("你沒有權限執行此指令。"));
            return true;
        }
        if (args.length == 0) {
            sendUsage(sender);
            return true;
        }
        switch (args[0].toLowerCase()) {
            case "reload" -> reload(sender);
            case "status" -> status(sender);
            case "clients" -> clients(sender);
            case "block" -> block(sender, args);
            case "unblock" -> unblock(sender, args);
            default -> sendUsage(sender);
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission(PERMISSION)) {
            return List.of();
        }
        if (args.length == 1) {
            return List.of("reload", "status", "clients", "block", "unblock").stream()
                    .filter(value -> value.startsWith(args[0].toLowerCase())).toList();
        }
        return List.of();
    }

    private void reload(CommandSender sender) {
        boolean started = plugin.reloadSecurity();
        sender.sendMessage(Component.text(started
                ? "RconSecurity 設定已重新載入。"
                : "RconSecurity 設定載入失敗，Gateway 未啟動。"));
    }

    private void status(CommandSender sender) {
        var gateway = plugin.gateway();
        var settings = plugin.settings();
        int connections = gateway == null ? 0 : gateway.connectionCount();
        int nonces = plugin.authManager() == null ? 0 : plugin.authManager().activeNonceCount();
        sender.sendMessage(Component.text("RconSecurity status: enabled=" + settings.enabled()
                + " running=" + (gateway != null && gateway.isRunning())
                + " connections=" + connections + " activeChallenges=" + nonces));
    }

    private void clients(CommandSender sender) {
        sender.sendMessage(Component.text("Configured clients:"));
        for (ClientCredential client : plugin.settings().clients().values()) {
            sender.sendMessage(Component.text("- " + client.id() + " enabled=" + client.enabled()));
        }
    }

    private void block(CommandSender sender, String[] args) {
        if (args.length != 2 || args[1].isBlank() || args[1].matches(".*\\s.*")) {
            sender.sendMessage(Component.text("用法：/rconsecurity block <ip>"));
            return;
        }
        if (plugin.rateLimiter() == null) {
            sender.sendMessage(Component.text("Secure RCON Gateway 目前未啟用。"));
            return;
        }
        plugin.rateLimiter().block(args[1]);
        sender.sendMessage(Component.text("已暫時封鎖 IP：" + args[1]));
    }

    private void unblock(CommandSender sender, String[] args) {
        if (args.length != 2 || args[1].isBlank() || args[1].matches(".*\\s.*")) {
            sender.sendMessage(Component.text("用法：/rconsecurity unblock <ip>"));
            return;
        }
        if (plugin.rateLimiter() == null) {
            sender.sendMessage(Component.text("Secure RCON Gateway 目前未啟用。"));
            return;
        }
        plugin.rateLimiter().unblock(args[1]);
        sender.sendMessage(Component.text("已解除 IP 封鎖：" + args[1]));
    }

    private void sendUsage(CommandSender sender) {
        sender.sendMessage(Component.text("用法：/rconsecurity <reload|status|clients|block|unblock>"));
    }
}
