/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.paper.protocol;

import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.handshaking.client.WrapperHandshakingClientHandshake;
import com.github.retrooper.packetevents.wrapper.login.server.WrapperLoginServerDisconnect;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.Bukkit;
import xyz.kyngs.librelogin.api.Logger;
import xyz.kyngs.librelogin.common.util.ProxyAuthUtil;

import java.util.HashSet;
import java.util.Set;

public class ProxyAuthVerifier extends PacketListenerAbstract {

    private final ProxyAuthClient client;
    private final boolean failOpen;
    private final String kickMessage;
    private final Object plugin;
    private final Logger logger;

    public ProxyAuthVerifier(ProxyAuthConfig config, Logger logger, Object plugin) {
        super(PacketListenerPriority.HIGHEST);
        String[] hostPort = ProxyAuthClient.parseServer(config.server());
        this.client = new ProxyAuthClient(hostPort[0], Integer.parseInt(hostPort[1]));
        this.failOpen = config.failOpen();
        this.kickMessage = config.kickMessage();
        this.plugin = plugin;
        this.logger = logger;
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        if (event.isCancelled()) return;
        if (event.getPacketType() != PacketType.Handshaking.Client.HANDSHAKE) return;

        var handshake = new WrapperHandshakingClientHandshake(event);
        String address = handshake.getServerAddress();
        if (address == null || address.isEmpty()) return;

        String[] parts = address.split("\0", -1);

        if (parts.length < 3) {
            reject(event, "missing proxy forwarding data");
            return;
        }

        String host = parts[0];
        String ip = parts[1];

        String ticket = ProxyAuthUtil.extractTicket(host);
        if (ticket == null) {
            reject(event, "connection did not come through the configured proxy (missing ticket)");
            return;
        }

        ProxyAuthClient.Result result = client.verify(ticket, ip);
        switch (result) {
            case OK -> logger.info("Connection from " + ip + " passed proxy authentication (server: " + ProxyAuthUtil.stripTicket(host) + ").");
            case NO -> {
                reject(event, "invalid proxy authentication ticket");
                return;
            }
            case UNREACHABLE -> {
                if (!failOpen) {
                    reject(event, "proxy authentication server unreachable");
                    return;
                }
                logger.warn("Proxy authentication server unreachable, failing open for " + event.getSocketAddress());
            }
        }

        parts[0] = ProxyAuthUtil.stripTicket(host);
        var rebuilt = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            rebuilt.append('\0').append(parts[i]);
        }
        handshake.setServerAddress(rebuilt.toString());
        event.setLastUsedWrapper(handshake);
        event.markForReEncode(true);
    }

    private void reject(PacketReceiveEvent event, String reason) {
        logger.warn("Rejected connection from " + event.getSocketAddress() + ": " + reason
                + ". Connections must come through the configured BungeeCord/Waterfall proxy (proxy-auth-server).");
        event.setCancelled(true);
        try {
            WrapperLoginServerDisconnect disconnect = new WrapperLoginServerDisconnect(legacyComponent(kickMessage));
            PacketEvents.getAPI().getProtocolManager().sendPacket(event.getChannel(), disconnect);
            Object channel = event.getChannel();
            Bukkit.getScheduler().runTaskLater((org.bukkit.plugin.Plugin) plugin, () -> {
                try {
                    channel.getClass().getMethod("close").invoke(channel);
                } catch (ReflectiveOperationException ignored) {
                }
            }, 3L);
        } catch (Exception e) {
            try {
                Object channel = event.getChannel();
                channel.getClass().getMethod("close").invoke(channel);
            } catch (ReflectiveOperationException ignored) {
            }
        }
    }

    private Component legacyComponent(String legacy) {
        StringBuilder text = new StringBuilder();
        NamedTextColor color = null;
        Set<TextDecoration> decorations = new HashSet<>();
        for (int i = 0; i < legacy.length(); i++) {
            char c = legacy.charAt(i);
            if (c == '&' && i + 1 < legacy.length()) {
                char code = Character.toLowerCase(legacy.charAt(i + 1));
                i++;
                switch (code) {
                    case '0' -> color = NamedTextColor.BLACK;
                    case '1' -> color = NamedTextColor.DARK_BLUE;
                    case '2' -> color = NamedTextColor.DARK_GREEN;
                    case '3' -> color = NamedTextColor.DARK_AQUA;
                    case '4' -> color = NamedTextColor.DARK_RED;
                    case '5' -> color = NamedTextColor.DARK_PURPLE;
                    case '6' -> color = NamedTextColor.GOLD;
                    case '7' -> color = NamedTextColor.GRAY;
                    case '8' -> color = NamedTextColor.DARK_GRAY;
                    case '9' -> color = NamedTextColor.BLUE;
                    case 'a' -> color = NamedTextColor.GREEN;
                    case 'b' -> color = NamedTextColor.AQUA;
                    case 'c' -> color = NamedTextColor.RED;
                    case 'd' -> color = NamedTextColor.LIGHT_PURPLE;
                    case 'e' -> color = NamedTextColor.YELLOW;
                    case 'f' -> color = NamedTextColor.WHITE;
                    case 'k' -> decorations.add(TextDecoration.OBFUSCATED);
                    case 'l' -> decorations.add(TextDecoration.BOLD);
                    case 'm' -> decorations.add(TextDecoration.STRIKETHROUGH);
                    case 'n' -> decorations.add(TextDecoration.UNDERLINED);
                    case 'o' -> decorations.add(TextDecoration.ITALIC);
                    case 'r' -> {
                        color = null;
                        decorations.clear();
                    }
                    default -> text.append(c);
                }
            } else {
                text.append(c);
            }
        }
        Component component = Component.text(text.toString());
        if (color != null) component = component.color(color);
        for (TextDecoration decoration : decorations) {
            component = component.decorate(decoration);
        }
        return component;
    }
}