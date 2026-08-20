/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

import com.github.retrooper.packetevents.PacketEvents;
import io.github.retrooper.packetevents.factory.spigot.SpigotPacketEventsBuilder;
import org.bukkit.plugin.java.JavaPlugin;

public final class VerifierPlugin extends JavaPlugin {

    @Override
    public void onEnable() {
        VerifierConfig config = VerifierConfig.read(getDataFolder());

        PacketEvents.setAPI(SpigotPacketEventsBuilder.build(this));
        PacketEvents.getAPI().getSettings()
                .checkForUpdates(false)
                .bStats(false);
        PacketEvents.getAPI().load();

        String server = config.getServer();
        if (server == null || server.isEmpty()) {
            getLogger().warning("This server runs under BungeeCord/Waterfall but 'proxy-auth-server' is empty.");
            getLogger().warning("Connections will NOT be verified.");
            return;
        }

        String[] hostPort;
        try {
            hostPort = AuthClient.parseServer(server);
        } catch (IllegalArgumentException e) {
            getLogger().severe(e.getMessage());
            return;
        }

        AuthClient client = new AuthClient(hostPort[0], Integer.parseInt(hostPort[1]));
        PacketEvents.getAPI().getEventManager().registerListener(new AuthVerifier(client, config.isFailOpen(), getLogger()));

        getLogger().info("Proxy authentication verification enabled. Only connections carrying a valid ticket from your proxy will be accepted.");

        new AutoUpdater(this, getFile(), config).start();
    }

    @Override
    public void onDisable() {
        try {
            if (PacketEvents.getAPI() != null) {
                PacketEvents.getAPI().terminate();
            }
        } catch (Exception ignored) {
        }
    }
}