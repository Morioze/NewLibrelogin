/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public final class ProxyAuthUtil {

    public static final String TICKET_MARKER = "|llt:";

    private static final SecureRandom RANDOM = new SecureRandom();

    private ProxyAuthUtil() {
    }

    public static String sanitizeIP(InetAddress address) {
        return address instanceof Inet6Address ? "[" + address.getHostAddress() + "]" : address.getHostAddress();
    }

    public static String generateTicket() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String attachTicket(String host, String ticket) {
        return host + TICKET_MARKER + ticket;
    }

    public static String stripTicket(String host) {
        int index = host.indexOf(TICKET_MARKER);
        return index < 0 ? host : host.substring(0, index);
    }

    public static String extractTicket(String host) {
        int index = host.indexOf(TICKET_MARKER);
        if (index < 0) return null;
        return host.substring(index + TICKET_MARKER.length());
    }

    public static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
        );
    }
}