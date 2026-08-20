/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.handshaking.client.WrapperHandshakingClientHandshake;

import java.util.logging.Logger;

public final class AuthVerifier extends PacketListenerAbstract {

    private final AuthClient client;
    private final boolean failOpen;
    private final Logger logger;

    public AuthVerifier(AuthClient client, boolean failOpen, Logger logger) {
        super(PacketListenerPriority.HIGHEST);
        this.client = client;
        this.failOpen = failOpen;
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
            Object channel = event.getChannel();
            channel.getClass().getMethod("close").invoke(channel);
        } catch (ReflectiveOperationException ignored) {
        }
    }
}