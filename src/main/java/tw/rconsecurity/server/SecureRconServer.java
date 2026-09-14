package tw.rconsecurity.server;

import tw.rconsecurity.RconSecurity;
import tw.rconsecurity.auth.AuthManager;
import tw.rconsecurity.config.ConfigManager;
import tw.rconsecurity.rcon.NativeRconClient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

public final class SecureRconServer {
    private final RconSecurity plugin;
    private final ConfigManager.Settings settings;
    private final AuthManager authManager;
    private final NativeRconClient nativeRconClient;
    private final Set<Socket> connections = ConcurrentHashMap.newKeySet();
    private final Semaphore connectionSlots;
    private final AtomicBoolean running = new AtomicBoolean();
    private ExecutorService acceptExecutor;
    private ExecutorService clientExecutor;
    private ServerSocket serverSocket;

    public SecureRconServer(RconSecurity plugin, ConfigManager.Settings settings,
                            AuthManager authManager, NativeRconClient nativeRconClient) {
        this.plugin = plugin;
        this.settings = settings;
        this.authManager = authManager;
        this.nativeRconClient = nativeRconClient;
        this.connectionSlots = new Semaphore(settings.security().maxConnections());
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            return;
        }
        InetAddress bindAddress = InetAddress.getByName(settings.host());
        ServerSocket newServerSocket = new ServerSocket(settings.port(), settings.security().maxConnections(), bindAddress);
        newServerSocket.setReuseAddress(true);
        serverSocket = newServerSocket;
        acceptExecutor = Executors.newSingleThreadExecutor(runnable -> namedThread(runnable, "rconsecurity-accept"));
        clientExecutor = Executors.newCachedThreadPool(runnable -> namedThread(runnable, "rconsecurity-client"));
        running.set(true);
        acceptExecutor.execute(this::acceptLoop);
        plugin.getLogger().info("Secure RCON Gateway listening on " + settings.host() + ":" + settings.port());
    }

    public synchronized void stop() {
        if (!running.getAndSet(false)) {
            return;
        }
        try {
            serverSocket.close();
        } catch (IOException ignored) {
        }
        for (Socket connection : connections) {
            closeQuietly(connection);
        }
        shutdown(acceptExecutor);
        shutdown(clientExecutor);
        connections.clear();
        plugin.getLogger().info("Secure RCON Gateway stopped.");
    }

    public boolean isRunning() {
        return running.get();
    }

    public int connectionCount() {
        return connections.size();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                if (!connectionSlots.tryAcquire()) {
                    closeQuietly(socket);
                    continue;
                }
                socket.setTcpNoDelay(true);
                connections.add(socket);
                clientExecutor.execute(() -> {
                    try {
                        new ClientConnection(plugin, socket, settings, authManager, nativeRconClient).run();
                    } finally {
                        connections.remove(socket);
                        connectionSlots.release();
                        closeQuietly(socket);
                    }
                });
            } catch (SocketException exception) {
                if (running.get()) {
                    plugin.getLogger().log(Level.WARNING, "Secure RCON accept failed", exception);
                }
            } catch (IOException exception) {
                if (running.get()) {
                    plugin.getLogger().log(Level.WARNING, "Secure RCON accept failed", exception);
                }
            }
        }
    }

    private Thread namedThread(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }

    private void shutdown(ExecutorService executor) {
        if (executor == null) {
            return;
        }
        executor.shutdownNow();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
