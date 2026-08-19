/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.paper.protocol;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class ProxyAuthClient {

    public enum Result {
        OK,
        NO,
        UNREACHABLE
    }

    private final String host;
    private final int port;

    public ProxyAuthClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public static String[] parseServer(String server) {
        String trimmed = server.trim();
        String host;
        String portPart;
        if (trimmed.startsWith("[")) {
            int close = trimmed.indexOf(']');
            if (close < 0) throw new IllegalArgumentException("Invalid proxy-auth-server: " + server);
            host = trimmed.substring(1, close);
            portPart = trimmed.substring(close + 1);
        } else {
            int colon = trimmed.lastIndexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Invalid proxy-auth-server: " + server);
            host = trimmed.substring(0, colon);
            portPart = trimmed.substring(colon + 1);
        }
        if (host.isEmpty() || !portPart.startsWith(":")) {
            throw new IllegalArgumentException("Invalid proxy-auth-server: " + server);
        }
        int port = Integer.parseInt(portPart.substring(1));
        if (port <= 0 || port > 65535) throw new IllegalArgumentException("Invalid proxy-auth-server: " + server);
        return new String[]{host, Integer.toString(port)};
    }

    public Result verify(String ticket, String ip) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 2000);
            socket.setSoTimeout(2000);
            var writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
            var reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            writer.write("VERIFY " + ticket + " " + ip + "\n");
            writer.flush();

            String response = reader.readLine();
            if ("OK".equals(response)) return Result.OK;
            if ("NO".equals(response)) return Result.NO;
            return Result.UNREACHABLE;
        } catch (IOException e) {
            return Result.UNREACHABLE;
        }
    }
}