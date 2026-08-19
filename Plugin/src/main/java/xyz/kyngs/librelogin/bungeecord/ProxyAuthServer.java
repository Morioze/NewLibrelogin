/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.bungeecord;

import xyz.kyngs.librelogin.api.Logger;
import xyz.kyngs.librelogin.common.util.ProxyAuthUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ProxyAuthServer {

    private static final long TICKET_LIFETIME_MILLIS = 24 * 60 * 60 * 1000L;

    private final Map<String, TicketEntry> tickets = new ConcurrentHashMap<>();
    private final Map<UUID, String> playerTickets = new ConcurrentHashMap<>();
    private final Logger logger;

    private volatile ServerSocket serverSocket;
    private volatile boolean running;
    private Thread acceptThread;
    private ExecutorService handlerPool;

    private static final class TicketEntry {
        final String ip;
        final long expiresAt;

        TicketEntry(String ip, long expiresAt) {
            this.ip = ip;
            this.expiresAt = expiresAt;
        }
    }

    public ProxyAuthServer(Logger logger) {
        this.logger = logger;
    }

    public boolean start(int port) {
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            logger.error("Failed to bind the proxy authentication verification port " + port + ": " + e.getMessage());
            return false;
        }
        running = true;
        handlerPool = Executors.newCachedThreadPool();
        acceptThread = new Thread(this::acceptLoop, "LibreLogin ProxyAuth Server");
        acceptThread.setDaemon(true);
        acceptThread.start();
        logger.info("Proxy authentication verification server listening on port " + port);
        return true;
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
        }
        if (handlerPool != null) handlerPool.shutdownNow();
        tickets.clear();
        playerTickets.clear();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                handlerPool.execute(() -> handle(socket));
            } catch (IOException e) {
                if (running) {
                    logger.warn("Proxy authentication verification server accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handle(Socket socket) {
        try (socket;
             var reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             var writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8)) {
            socket.setSoTimeout(3000);
            String line = reader.readLine();
            if (line == null) return;
            String response;
            if (line.equals("PING")) {
                response = "PONG";
            } else if (line.startsWith("VERIFY ")) {
                String[] parts = line.substring("VERIFY ".length()).split(" ", 2);
                response = (parts.length == 2 && verify(parts[0], parts[1])) ? "OK" : "NO";
            } else {
                response = "NO";
            }
            writer.write(response + "\n");
            writer.flush();
        } catch (IOException ignored) {
        }
    }

    public String issueTicket(InetAddress address) {
        String ticket = ProxyAuthUtil.generateTicket();
        tickets.put(ticket, new TicketEntry(
                address.getHostAddress(),
                System.currentTimeMillis() + TICKET_LIFETIME_MILLIS
        ));
        return ticket;
    }

    public void bind(UUID player, String ticket) {
        if (ticket != null) playerTickets.put(player, ticket);
    }

    public void unbind(UUID player) {
        String ticket = playerTickets.remove(player);
        if (ticket != null) tickets.remove(ticket);
    }

    public boolean verify(String ticket, String ip) {
        TicketEntry entry = tickets.get(ticket);
        if (entry == null) return false;
        if (entry.expiresAt < System.currentTimeMillis()) {
            tickets.remove(ticket);
            return false;
        }
        return ProxyAuthUtil.constantTimeEquals(entry.ip, ip);
    }

    public void prune() {
        long now = System.currentTimeMillis();
        tickets.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
    }
}