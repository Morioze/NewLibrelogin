/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

public final class AutoUpdater implements Runnable {

    private final JavaPlugin plugin;
    private final File jarFile;
    private final VerifierConfig config;

    public AutoUpdater(JavaPlugin plugin, File jarFile, VerifierConfig config) {
        this.plugin = plugin;
        this.jarFile = jarFile;
        this.config = config;
    }

    public void start() {
        if (!config.isAutoUpdate()) return;
        plugin.getLogger().info("Auto-update enabled: checking " + config.getAutoUpdateUrl()
                + " every " + config.getAutoUpdateInterval() + " seconds.");
        long ticks = config.getAutoUpdateInterval() * 20L;
        Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, this, ticks, ticks);
    }

    @Override
    public void run() {
        try {
            File running = jarFile;
            String runningHash = sha256(running);
            File downloaded = download(config.getAutoUpdateUrl());
            if (downloaded == null) return;
            String newHash = sha256(downloaded);
            if (runningHash.equals(newHash)) {
                downloaded.delete();
                return;
            }
            File jarFolder = running.getParentFile();
            File old = new File(jarFolder, running.getName() + ".old");
            if (old.exists()) old.delete();
            try {
                Files.move(running.toPath(), old.toPath(), StandardCopyOption.REPLACE_EXISTING);
                Files.move(downloaded.toPath(), running.toPath(), StandardCopyOption.REPLACE_EXISTING);
                plugin.getLogger().info("LibreLoginVerifier updated. Restarting the server to apply the update...");
                Bukkit.getScheduler().runTask(plugin, new Runnable() {
                    @Override
                    public void run() {
                        Bukkit.shutdown();
                    }
                });
            } catch (IOException e) {
                plugin.getLogger().warning("Could not replace the plugin jar: " + e.getMessage()
                        + ". Save the new file manually.");
                downloaded.delete();
            }
        } catch (Exception e) {
            plugin.getLogger().warning("Auto-update check failed: " + e.getMessage());
        }
    }

    private File download(String urlString) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(urlString).openConnection();
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setInstanceFollowRedirects(true);
        int code = connection.getResponseCode();
        if (code != 200) {
            connection.disconnect();
            return null;
        }
        File temp = new File(plugin.getDataFolder(), "update.jar");
        InputStream in = connection.getInputStream();
        FileOutputStream out = new FileOutputStream(temp);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        out.close();
        in.close();
        connection.disconnect();
        return temp;
    }

    private String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        InputStream in = Files.newInputStream(file.toPath());
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        in.close();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest.digest()) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}