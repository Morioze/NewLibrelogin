/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.paper.protocol;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.handshaking.client.WrapperHandshakingClientHandshake;
import xyz.kyngs.librelogin.api.Logger;
import xyz.kyngs.librelogin.common.util.ProxyAuthUtil;

public class ProxyAuthVerifier extends PacketListenerAbstract {

    private final ProxyAuthClient client;
    private final boolean failOpen;
    private final Logger logger;

    public ProxyAuthVerifier(ProxyAuthConfig config, Logger logger) {
        super(PacketListenerPriority.HIGHEST);
        String[] hostPort = ProxyAuthClient.parseServer(config.server());
        this.client = new ProxyAuthClient(hostPort[0], Integer.parseInt(hostPort[1]));
        this.failOpen = config.failOpen();
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
            Object channel = event.getChannel();
            channel.getClass().getMethod("close").invoke(channel);
        } catch (ReflectiveOperationException ignored) {
        }
    }
}