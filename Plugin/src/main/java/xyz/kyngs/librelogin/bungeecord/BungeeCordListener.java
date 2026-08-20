/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.bungeecord;

import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.*;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;
import xyz.kyngs.librelogin.api.event.exception.EventCancelledException;
import xyz.kyngs.librelogin.common.config.ConfigurationKeys;
import xyz.kyngs.librelogin.common.listener.AuthenticListeners;
import xyz.kyngs.librelogin.common.util.GeneralUtil;
import xyz.kyngs.librelogin.common.util.ProxyAuthUtil;
import xyz.kyngs.librelogin.common.util.RateLimiter;

import java.lang.reflect.Field;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static net.md_5.bungee.event.EventPriority.HIGHEST;
import static net.md_5.bungee.event.EventPriority.LOW;

public class BungeeCordListener extends AuthenticListeners<BungeeCordLibreLogin, ProxiedPlayer, ServerInfo> implements Listener {

    private final RateLimiter<UUID> limboRedirectLimiter;

    public BungeeCordListener(BungeeCordLibreLogin plugin) {
        super(plugin);
        limboRedirectLimiter = new RateLimiter<>(5000, TimeUnit.MILLISECONDS);
    }

    public void runAsyncEvent(AsyncEvent<?> event, Runnable runnable) {
        event.registerIntent(plugin.getBootstrap());

        GeneralUtil.ASYNC_POOL.execute(() -> {
            try {
                runnable.run();
            } finally {
                event.completeIntent(plugin.getBootstrap());
            }
        });
    }

    @EventHandler(priority = HIGHEST)
    public void onPostLogin(PostLoginEvent event) {
        var proxyAuthServer = plugin.getProxyAuthServer();
        if (proxyAuthServer != null) {
            proxyAuthServer.bind(event.getPlayer().getUniqueId(), extractPendingTicket(event.getPlayer().getPendingConnection()));
        }
        runAsyncEvent(event, () -> onPostLogin(event.getPlayer(), null));
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        var proxyAuthServer = plugin.getProxyAuthServer();
        if (proxyAuthServer != null) proxyAuthServer.unbind(event.getPlayer().getUniqueId());
        onPlayerDisconnect(event.getPlayer());
    }

    @EventHandler(priority = HIGHEST)
    public void onPreLogin(PreLoginEvent event) {
        if (plugin.fromFloodgate(event.getConnection().getUniqueId())) return;

        runAsyncEvent(event, () -> {
            var result = onPreLogin(event.getConnection().getName(), event.getConnection().getAddress().getAddress());

            switch (result.state()) {
                case DENIED -> {
                    assert result.message() != null;
                    event.setCancelled(true);
                    event.setCancelReason(plugin.getSerializer().serialize(result.message()));
                }
                case FORCE_ONLINE -> event.getConnection().setOnlineMode(true);
                case FORCE_OFFLINE -> event.getConnection().setOnlineMode(false);
            }
        });
    }

    @EventHandler(priority = HIGHEST)
    public void onPlayerHandshake(PlayerHandshakeEvent event) {
        var proxyAuthServer = plugin.getProxyAuthServer();
        if (proxyAuthServer == null) return;

        try {
            var handshake = PlayerHandshakeEvent.class.getMethod("getHandshake").invoke(event);
            if (handshake == null) return;

            var handshakeClass = handshake.getClass();
            int requestedProtocol = (int) handshakeClass.getMethod("getRequestedProtocol").invoke(handshake);
            if (requestedProtocol != 2 && requestedProtocol != 3) return;

            String host = (String) handshakeClass.getMethod("getHost").invoke(handshake);
            if (host == null || host.isEmpty()) return;

            String ticket = proxyAuthServer.issueTicket(event.getConnection().getAddress().getAddress());

            handshakeClass.getMethod("setHost", String.class).invoke(handshake, ProxyAuthUtil.attachTicket(host, ticket));
        } catch (ReflectiveOperationException e) {
            plugin.getLogger().error("Failed to attach the proxy authentication ticket to the handshake", e);
        }
    }

    private String extractPendingTicket(PendingConnection connection) {
        try {
            var handshake = connection.getClass().getMethod("getHandshake").invoke(connection);
            if (handshake == null) return null;
            String host = (String) handshake.getClass().getMethod("getHost").invoke(handshake);
            return ProxyAuthUtil.extractTicket(host);
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }

    private void setField(PendingConnection connection, String fieldName, Object value, boolean failOnNotFound) throws NoSuchFieldException {
        Class<?> clazz = connection.getClass();
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(connection, value);
        } catch (NoSuchFieldException e) {
            if (!failOnNotFound) return;
            var logger = super.plugin.getLogger();
            logger.error("The " + fieldName + " field was not found in the PendingConnection class, please report this to the developer. And attach the class summary below.");
            logger.error("-- BEGIN CLASS SUMMARY --");
            logger.error("Class: " + clazz.getName());
            for (Field field : clazz.getDeclaredFields()) {
                logger.error(field.getType().getName() + ": " + field.getName());
            }
            logger.error("-- END CLASS SUMMARY --");
            throw e;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onProfileRequest(LoginEvent event) {
        if (plugin.fromFloodgate(event.getConnection().getUniqueId())) return;

        // Note to future self: NEVER EVER RUN THIS ASYNC, IT WILL BREAK PLUGINS

        var profile = plugin.getDatabaseProvider().getByName(event.getConnection().getName());
        PendingConnection connection = event.getConnection();

        try {
            setField(connection, "uniqueId", profile.getUuid(), true);
            setField(connection, "rewriteId", profile.getUuid(), false);
            //setField(connection, "offlineId", profile.getUuid(), false);
        } catch (NoSuchFieldException e) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = HIGHEST)
    public void chooseServer(ServerConnectEvent event) {
        if (!event.getReason().equals(ServerConnectEvent.Reason.JOIN_PROXY)) return;

        var server = chooseServer(event.getPlayer(), null, null);

        if (server.value() == null) {
            event.getPlayer().disconnect(plugin.getSerializer().serialize(plugin.getMessages().getMessage("kick-no-" + (server.key() ? "lobby" : "limbo"))));
        } else {
            event.setTarget(server.value());
        }
    }

    @EventHandler(priority = HIGHEST)
    public void onServerConnected(ServerConnectedEvent event) {
        var player = event.getPlayer();
        var limboServers = plugin.getConfiguration().get(ConfigurationKeys.LIMBO);

        if (!limboServers.contains(event.getServer().getInfo().getName())) return;

        if (!plugin.getConfiguration().get(ConfigurationKeys.REDIRECT_AUTHORIZED_PLAYERS_FROM_LIMBO)) return;

        if (!plugin.getAuthorizationProvider().isAuthorized(player)) return;

        if (limboRedirectLimiter.tryAndLimit(player.getUniqueId())) return;

        plugin.delay(() -> {
            if (!player.isConnected()) return;
            if (player.getServer() == null || !limboServers.contains(player.getServer().getInfo().getName())) return;

            try {
                var user = plugin.getDatabaseProvider().getByUUID(player.getUniqueId());
                var lobby = plugin.getServerHandler().chooseLobbyServer(user, player, true, false);
                if (lobby != null) player.connect(lobby);
            } catch (EventCancelledException ignored) {}
        }, 100);
    }

    @EventHandler(priority = LOW)
    public void onKick(ServerKickEvent event) {
        var reason = plugin.getSerializer().deserialize(event.getKickReasonComponent());
        var message = plugin.getMessages().getMessage("info-kick").replaceText(builder -> builder.matchLiteral("%reason%").replacement(reason));
        var player = event.getPlayer();
        var audience = platformHandle.getAudienceForPlayer(event.getPlayer());

        if (event.getState() == ServerKickEvent.State.CONNECTED) {
            if (!plugin.getConfiguration().get(ConfigurationKeys.FALLBACK)) {
                event.setKickReasonComponent(plugin.getSerializer().serialize(message));
                event.setCancelled(false);
            } else {
                try {
                    var server = plugin.getServerHandler().chooseLobbyServer(plugin.getDatabaseProvider().getByUUID(player.getUniqueId()), player, false, true);

                    if (server == null) throw new NoSuchElementException();

                    event.setCancelled(true);
                    event.setCancelServer(server);
                } catch (NoSuchElementException | EventCancelledException e) {
                    event.setKickReasonComponent(plugin.getSerializer().serialize(message));
                    event.setCancelled(false);
                }
            }
        } else {
            audience.sendMessage(message);
        }
    }

}
