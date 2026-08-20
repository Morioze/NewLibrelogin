/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.verifier;

public final class TicketUtil {

    public static final String TICKET_MARKER = "|llt:";

    private TicketUtil() {
    }

    public static String attachTicket(String host, String ticket) {
        return host + TICKET_MARKER + ticket;
    }

    public static String extractTicket(String host) {
        int index = host.indexOf(TICKET_MARKER);
        if (index < 0) return null;
        return host.substring(index + TICKET_MARKER.length());
    }

    public static String stripTicket(String host) {
        int index = host.indexOf(TICKET_MARKER);
        return index < 0 ? host : host.substring(0, index);
    }
}