/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

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
import org.bukkit.plugin.java.JavaPlugin;

import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

public final class AuthVerifier extends PacketListenerAbstract {

    private final AuthClient client;
    private final boolean failOpen;
    private final String kickMessage;
    private final JavaPlugin plugin;
    private final Logger logger;

    public AuthVerifier(AuthClient client, boolean failOpen, String kickMessage, JavaPlugin plugin, Logger logger) {
        super(PacketListenerPriority.HIGHEST);
        this.client = client;
        this.failOpen = failOpen;
        this.kickMessage = kickMessage;
        this.plugin = plugin;
        this.logger = logger;
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        if (event.isCancelled()) return;
        if (event.getPacketType() != PacketType.Handshaking.Client.HANDSHAKE) return;

        WrapperHandshakingClientHandshake handshake = new WrapperHandshakingClientHandshake(event);
        String address = handshake.getServerAddress();
        if (address == null || address.isEmpty()) return;

        String[] parts = address.split("\0", -1);

        if (parts.length < 3) {
            reject(event, "missing proxy forwarding data");
            return;
        }

        String host = parts[0];
        String ip = parts[1];

        String ticket = TicketUtil.extractTicket(host);
        if (ticket == null) {
            reject(event, "connection did not come through the configured proxy (missing ticket)");
            return;
        }

        AuthClient.Result result = client.verify(ticket, ip);
        if (result == AuthClient.Result.OK) {
            logger.info("Connection from " + ip + " passed proxy authentication (server: " + TicketUtil.stripTicket(host) + ").");
        } else if (result == AuthClient.Result.NO) {
            reject(event, "invalid proxy authentication ticket");
            return;
        } else {
            if (!failOpen) {
                reject(event, "proxy authentication server unreachable");
                return;
            }
            logger.warning("Proxy authentication server unreachable, failing open for " + event.getSocketAddress());
        }

        parts[0] = TicketUtil.stripTicket(host);
        StringBuilder rebuilt = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            rebuilt.append('\0').append(parts[i]);
        }
        handshake.setServerAddress(rebuilt.toString());
        event.setLastUsedWrapper(handshake);
        event.markForReEncode(true);
    }

    private void reject(PacketReceiveEvent event, String reason) {
        logger.warning("Rejected connection from " + event.getSocketAddress() + ": " + reason
                + ". Connections must come through the configured BungeeCord/Waterfall proxy (proxy-auth-server).");
        event.setCancelled(true);
        try {
            WrapperLoginServerDisconnect disconnect = new WrapperLoginServerDisconnect(legacyComponent(kickMessage));
            PacketEvents.getAPI().getProtocolManager().sendPacket(event.getChannel(), disconnect);
            final Object channel = event.getChannel();
            Bukkit.getScheduler().runTaskLater(plugin, new Runnable() {
                @Override
                public void run() {
                    try {
                        channel.getClass().getMethod("close").invoke(channel);
                    } catch (ReflectiveOperationException ignored) {
                    }
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
        Set<TextDecoration> decorations = new HashSet<TextDecoration>();
        for (int i = 0; i < legacy.length(); i++) {
            char c = legacy.charAt(i);
            if (c == '&' && i + 1 < legacy.length()) {
                char code = Character.toLowerCase(legacy.charAt(i + 1));
                i++;
                switch (code) {
                    case '0': color = NamedTextColor.BLACK; break;
                    case '1': color = NamedTextColor.DARK_BLUE; break;
                    case '2': color = NamedTextColor.DARK_GREEN; break;
                    case '3': color = NamedTextColor.DARK_AQUA; break;
                    case '4': color = NamedTextColor.DARK_RED; break;
                    case '5': color = NamedTextColor.DARK_PURPLE; break;
                    case '6': color = NamedTextColor.GOLD; break;
                    case '7': color = NamedTextColor.GRAY; break;
                    case '8': color = NamedTextColor.DARK_GRAY; break;
                    case '9': color = NamedTextColor.BLUE; break;
                    case 'a': color = NamedTextColor.GREEN; break;
                    case 'b': color = NamedTextColor.AQUA; break;
                    case 'c': color = NamedTextColor.RED; break;
                    case 'd': color = NamedTextColor.LIGHT_PURPLE; break;
                    case 'e': color = NamedTextColor.YELLOW; break;
                    case 'f': color = NamedTextColor.WHITE; break;
                    case 'k': decorations.add(TextDecoration.OBFUSCATED); break;
                    case 'l': decorations.add(TextDecoration.BOLD); break;
                    case 'm': decorations.add(TextDecoration.STRIKETHROUGH); break;
                    case 'n': decorations.add(TextDecoration.UNDERLINED); break;
                    case 'o': decorations.add(TextDecoration.ITALIC); break;
                    case 'r': color = null; decorations.clear(); break;
                    default: text.append(c); break;
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