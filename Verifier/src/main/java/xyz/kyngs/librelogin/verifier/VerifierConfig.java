/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public final class VerifierConfig {

    public static final String DEFAULT_SERVER = "127.0.0.1:48777";
    public static final String DEFAULT_AUTO_UPDATE_URL = "https://github.com/Morioze/NewLibrelogin/releases/download/a/LibreLoginVerifier.jar";
    public static final String DEFAULT_KICK_MESSAGE = "&c&l请勿非法加入！";

    private static final String TEMPLATE =
            "# LibreLoginVerifier configuration (Java 8 backend).\n" +
            "# This server runs under BungeeCord/Waterfall. This plugin only verifies that\n" +
            "# every connection comes from your proxy.\n" +
            "#\n" +
            "# Point 'proxy-auth-server' to your proxy and set 'proxy-auth-verify-port' on the\n" +
            "# proxy to reject any connection that does NOT carry a valid ticket from your proxy.\n" +
            "# If your proxy runs on a different machine than this server, change this address.\n" +
            "proxy-auth-server = \"127.0.0.1:48777\"\n" +
            "\n" +
            "# Message shown to players whose connection is rejected.\n" +
            "kick-message = \"&c&l请勿非法加入！\"\n" +
            "\n" +
            "# If the proxy is unreachable, accept the connection anyway (true) or reject it (false).\n" +
            "# Keep false for maximum protection.\n" +
            "proxy-auth-fail-open = false\n" +
            "\n" +
            "# Verbose logging.\n" +
            "debug = false\n" +
            "\n" +
            "# Automatic updates: downloads a new build from auto-update-url, replaces this jar\n" +
            "# and restarts the server when a newer version is found.\n" +
            "auto-update = true\n" +
            "auto-update-url = \"https://github.com/Morioze/NewLibrelogin/releases/download/a/LibreLoginVerifier.jar\"\n" +
            "auto-update-interval = 43200\n";

    private final String server;
    private final String kickMessage;
    private final boolean failOpen;
    private final boolean debug;
    private final boolean autoUpdate;
    private final String autoUpdateUrl;
    private final long autoUpdateInterval;

    public VerifierConfig(String server, String kickMessage, boolean failOpen, boolean debug, boolean autoUpdate, String autoUpdateUrl, long autoUpdateInterval) {
        this.server = server;
        this.kickMessage = kickMessage;
        this.failOpen = failOpen;
        this.debug = debug;
        this.autoUpdate = autoUpdate;
        this.autoUpdateUrl = autoUpdateUrl;
        this.autoUpdateInterval = autoUpdateInterval;
    }

    public String getServer() {
        return server;
    }

    public String getKickMessage() {
        return kickMessage;
    }

    public boolean isFailOpen() {
        return failOpen;
    }

    public boolean isDebug() {
        return debug;
    }

    public boolean isAutoUpdate() {
        return autoUpdate;
    }

    public String getAutoUpdateUrl() {
        return autoUpdateUrl;
    }

    public long getAutoUpdateInterval() {
        return autoUpdateInterval;
    }

    public static VerifierConfig read(File dataFolder) {
        File file = new File(dataFolder, "config.conf");
        if (!file.isFile()) {
            writeTemplate(dataFolder, file);
            return defaults();
        }
        try {
            String server = DEFAULT_SERVER;
            String kickMessage = DEFAULT_KICK_MESSAGE;
            boolean failOpen = false;
            boolean debug = false;
            boolean autoUpdate = true;
            String autoUpdateUrl = DEFAULT_AUTO_UPDATE_URL;
            long autoUpdateInterval = 43200L;
            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            for (String line : lines) {
                String cleaned = stripComment(line).trim();
                if (cleaned.isEmpty()) continue;
                int eq = indexOfAssignment(cleaned);
                if (eq < 0) continue;
                String key = cleaned.substring(0, eq).trim();
                String value = cleaned.substring(eq + 1).trim();
                if (key.equals("proxy-auth-server")) {
                    server = unquote(value);
                } else if (key.equals("kick-message")) {
                    kickMessage = unquote(value);
                } else if (key.equals("proxy-auth-fail-open")) {
                    failOpen = Boolean.parseBoolean(value);
                } else if (key.equals("debug")) {
                    debug = Boolean.parseBoolean(value);
                } else if (key.equals("auto-update")) {
                    autoUpdate = Boolean.parseBoolean(value);
                } else if (key.equals("auto-update-url")) {
                    autoUpdateUrl = unquote(value);
                } else if (key.equals("auto-update-interval")) {
                    autoUpdateInterval = Long.parseLong(value);
                }
            }
            return new VerifierConfig(server, kickMessage, failOpen, debug, autoUpdate, autoUpdateUrl, autoUpdateInterval);
        } catch (Exception e) {
            return defaults();
        }
    }

    private static VerifierConfig defaults() {
        return new VerifierConfig(DEFAULT_SERVER, DEFAULT_KICK_MESSAGE, false, false, true, DEFAULT_AUTO_UPDATE_URL, 43200L);
    }

    private static void writeTemplate(File dataFolder, File file) {
        try {
            if (!dataFolder.exists() && !dataFolder.mkdirs()) return;
            Files.write(file.toPath(), TEMPLATE.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
    }

    private static int indexOfAssignment(String line) {
        boolean inString = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inString = !inString;
            } else if ((c == '=' || c == ':') && !inString) {
                return i;
            }
        }
        return -1;
    }

    private static String stripComment(String line) {
        boolean inString = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inString = !inString;
            } else if (!inString && (c == '#' || (c == '/' && i + 1 < line.length() && line.charAt(i + 1) == '/'))) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1)
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
        }
        return value;
    }
}