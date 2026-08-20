/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.paper.protocol;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public record ProxyAuthConfig(String server, boolean failOpen, boolean debug, boolean autoUpdate, String autoUpdateUrl, long autoUpdateInterval) {

    public static final String DEFAULT_AUTO_UPDATE_URL = "https://github.com/Morioze/NewLibrelogin/releases/download/a/LibreLogin.jar";

    public static ProxyAuthConfig read(File dataFolder) {
        var file = new File(dataFolder, "config.conf");
        if (!file.isFile()) {
            return new ProxyAuthConfig("", false, false, true, DEFAULT_AUTO_UPDATE_URL, 43200L);
        }
        try {
            String server = "";
            boolean failOpen = false;
            boolean debug = false;
            boolean autoUpdate = true;
            String autoUpdateUrl = DEFAULT_AUTO_UPDATE_URL;
            long autoUpdateInterval = 43200L;
            for (var line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
                var cleaned = stripComment(line).trim();
                if (cleaned.isEmpty()) continue;
                int eq = indexOfAssignment(cleaned);
                if (eq < 0) continue;
                var key = cleaned.substring(0, eq).trim();
                var value = cleaned.substring(eq + 1).trim();
                if (key.equals("proxy-auth-server")) {
                    server = unquote(value);
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
            return new ProxyAuthConfig(server, failOpen, debug, autoUpdate, autoUpdateUrl, autoUpdateInterval);
        } catch (Exception e) {
            return new ProxyAuthConfig("", false, false, true, DEFAULT_AUTO_UPDATE_URL, 43200L);
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