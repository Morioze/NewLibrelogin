/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common.listener;

import org.jetbrains.annotations.Nullable;
import xyz.kyngs.librelogin.api.BiHolder;
import xyz.kyngs.librelogin.api.PlatformHandle;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.api.event.events.AuthenticatedEvent;
import xyz.kyngs.librelogin.api.premium.PremiumException;
import xyz.kyngs.librelogin.api.premium.PremiumUser;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.authorization.ProfileConflictResolutionStrategy;
import xyz.kyngs.librelogin.common.command.InvalidCommandArgument;
import xyz.kyngs.librelogin.common.config.ConfigurationKeys;
import xyz.kyngs.librelogin.common.database.AuthenticUser;
import xyz.kyngs.librelogin.common.event.events.AuthenticAuthenticatedEvent;

import java.net.InetAddress;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.regex.Pattern;

public class AuthenticListeners<Plugin extends AuthenticLibreLogin<P, S>, P, S> {

    private static final Pattern NAME_PATTERN = Pattern.compile("[\\p{L}\\p{N}_]*");

    protected final Plugin plugin;
    protected final PlatformHandle<P, S> platformHandle;

    public AuthenticListeners(Plugin plugin) {
        this.plugin = plugin;
        platformHandle = plugin.getPlatformHandle();
    }

    protected void onPostLogin(P player, User user) {
        var ip = platformHandle.getIP(player);
        var uuid = platformHandle.getUUIDForPlayer(player);
        if (plugin.fromFloodgate(uuid)) return;

        if (plugin.getConfiguration().get(ConfigurationKeys.DEBUG)) {
            plugin.getLogger().debug("onPostLogin() fired for %s".formatted(platformHandle.getUsernameForPlayer(player)));
        }

        if (user == null) {
            user = plugin.getDatabaseProvider().getByUUID(uuid);
        }

        var sessionStatus = getSessionStatus(user, ip);

        if (user.autoLoginEnabled()) {
            plugin.delay(() -> plugin.getPlatformHandle().getAudienceForPlayer(player).sendMessage(plugin.getMessages().getMessage("info-premium-logged-in")), 500);
            plugin.getEventProvider().fire(plugin.getEventTypes().authenticated, new AuthenticAuthenticatedEvent<>(user, player, plugin, AuthenticatedEvent.AuthenticationReason.PREMIUM));
        } else if (sessionStatus == SessionStatus.VALID) {
            plugin.delay(() -> plugin.getPlatformHandle().getAudienceForPlayer(player).sendMessage(plugin.getMessages().getMessage("info-session-logged-in")), 500);
            plugin.getEventProvider().fire(plugin.getEventTypes().authenticated, new AuthenticAuthenticatedEvent<>(user, player, plugin, AuthenticatedEvent.AuthenticationReason.SESSION));
        } else {
            if (sessionStatus == SessionStatus.IP_MISMATCH) {
                plugin.getLogger().warn("Security: player %s joined from IP %s, but their active session was bound to IP %s. Auto-login has been stopped and the session has been revoked.".formatted(user.getLastNickname(), ip, user.getIp()));
                user.setLastAuthentication(null);
                plugin.delay(() -> plugin.getPlatformHandle().getAudienceForPlayer(player).sendMessage(plugin.getMessages().getMessage("info-session-ip-changed")), 500);
            }
            plugin.getAuthorizationProvider().startTracking(user, player);
        }

        user.setLastSeen(Timestamp.valueOf(LocalDateTime.now()));

        var finalUser = user;
        plugin.delay(() -> plugin.getDatabaseProvider().updateUser(finalUser), 0);

    }

    protected void onPlayerDisconnect(P player) {
        plugin.onExit(player);
        plugin.getAuthorizationProvider().onExit(player);
    }

    protected PreLoginResult onPreLogin(String username, InetAddress address) {
        if (username.length() > 16 || !NAME_PATTERN.matcher(username).matches()) {
            return new PreLoginResult(PreLoginState.DENIED, plugin.getMessages().getMessage("kick-illegal-username"), null);
        }

        PremiumUser mojangData;

        try {
            mojangData = plugin.getPremiumProvider().getUserForName(username);
        } catch (PremiumException e) {
            var message = switch (e.getIssue()) {
                case THROTTLED -> plugin.getMessages().getMessage("kick-premium-error-throttled");
                default -> {
                    plugin.getLogger().error("Encountered an exception while communicating with the Mojang API!");
                    e.printStackTrace();
                    yield plugin.getMessages().getMessage("kick-premium-error-undefined");
                }
            };

            return new PreLoginResult(PreLoginState.DENIED, message, null);
        }

        if (mojangData == null) {
            // A user with this name does not exist in the Mojang database. It is impossible for this user to be premium.
            User user;
            try {
                user = checkAndValidateByName(username, null, true, address);
            } catch (InvalidCommandArgument e) {
                return new PreLoginResult(PreLoginState.DENIED, e.getUserFuckUp(), null);
            }

            //noinspection ConstantConditions //kyngs: There's no way IntelliJ is right
            if (user.getPremiumUUID() != null) {
                // We will have to encrypt, otherwise someone could forcefully disable other user's premium autologin
                return new PreLoginResult(PreLoginState.FORCE_ONLINE, null, user);
            }
        } else {

            // A user with this name exists in the Mojang database, we need to figure out whether to encrypt
            var premiumID = mojangData.uuid();
            var user = plugin.getDatabaseProvider().getByPremiumUUID(premiumID);

            if (user == null) {
                User userByName;
                try {
                    userByName = checkAndValidateByName(username, mojangData, true, address);
                } catch (InvalidCommandArgument e) {
                    return new PreLoginResult(PreLoginState.DENIED, e.getUserFuckUp(), null);
                }

                // The following condition may be true if we've generated a new user
                //noinspection ConstantConditions //kyngs: There's no way IntelliJ is right
                if (userByName.autoLoginEnabled())
                    return new PreLoginResult(PreLoginState.FORCE_ONLINE, null, userByName);
            } else {
                User byName;
                try {
                    byName = checkAndValidateByName(username, mojangData, false, address);
                } catch (InvalidCommandArgument e) {
                    return new PreLoginResult(PreLoginState.DENIED, e.getUserFuckUp(), null);
                }

                if (byName != null && !user.equals(byName)) {
                    // A user with this name already exists, however, it is not the same user as the premium one.
                    return handleProfileConflict(user, byName);
                }

                if (!mojangData.reliable()) {
                    plugin.getLogger().warn("User %s has probably changed their name. Data returned from Mojang API is not reliable, faking a new one using the current nickname.".formatted(username));
                    mojangData = new PremiumUser(mojangData.uuid(), username, false);
                }

                if (!user.getLastNickname().contentEquals(mojangData.name())) {
                    // User changed nickname, update DB
                    user.setLastNickname(mojangData.name());

                    plugin.getDatabaseProvider().updateUser(user);
                }

                return new PreLoginResult(PreLoginState.FORCE_ONLINE, null, user);
            }
        }

        return new PreLoginResult(PreLoginState.FORCE_OFFLINE, null, null);
    }

    private PreLoginResult handleProfileConflict(User conflicting, User conflicted) {
        return switch (ProfileConflictResolutionStrategy.valueOf(plugin.getConfiguration().get(ConfigurationKeys.PROFILE_CONFLICT_RESOLUTION_STRATEGY))) {
            case BLOCK -> new PreLoginResult(PreLoginState.DENIED, plugin.getMessages().getMessage("kick-name-mismatch",
                    "%nickname%", conflicting.getLastNickname()
            ), null);
            case USE_OFFLINE -> new PreLoginResult(PreLoginState.FORCE_OFFLINE, null, null);
            case OVERWRITE -> {
                plugin.getDatabaseProvider().deleteUser(conflicted);
                conflicting.setLastNickname(conflicted.getLastNickname());
                plugin.getDatabaseProvider().updateUser(conflicting);
                yield new PreLoginResult(PreLoginState.FORCE_ONLINE, null, conflicting);
            }
        };

    }

    /**
     * Checks and validates a user by their username.
     *
     * @param username  The username of the user.
     * @param premiumUser The premium user.
     * @param generate  True if a new user should be generated if the user doesn't exist, false otherwise.
     * @param ip        The IP address of the user.
     * @return The validated user, or null if the user doesn't exist and {@code generate} is false.
     * @throws InvalidCommandArgument If the username is invalid or there are other validation issues.
     */
    private User checkAndValidateByName(String username, @Nullable PremiumUser premiumUser, boolean generate, InetAddress ip) throws InvalidCommandArgument {
        // Get the user by the name not case-sensitively
        var user = plugin.getDatabaseProvider().getByName(username);

        if (user != null) {
            // Check for casing mismatch
            if (!user.getLastNickname().contentEquals(username)) {
                throw new InvalidCommandArgument(plugin.getMessages().getMessage("kick-invalid-case-username",
                        "%username%", user.getLastNickname()
                ));
            }
        } else if (generate) {
            var minLength = plugin.getConfiguration().get(ConfigurationKeys.MINIMUM_USERNAME_LENGTH);
            if (username.length() < minLength) {
                throw new InvalidCommandArgument(plugin.getMessages().getMessage("kick-short-username",
                        "%length%", String.valueOf(minLength)
                ));
            }

            var ipLimit = plugin.getConfiguration().get(ConfigurationKeys.IP_LIMIT);
            if (ipLimit > 0) {
                var ipCount = plugin.getDatabaseProvider().getByIP(ip.getHostAddress()).size(); // Ideally, this should be a count query, but I'm too lazy to implement that and the performance impact is negligible.

                if (ipCount >= ipLimit) {
                    throw new InvalidCommandArgument(plugin.getMessages().getMessage("kick-ip-limit",
                            "%limit%", String.valueOf(ipLimit)
                    ));
                }
            }

            var newID = plugin.generateNewUUID(
                    username,
                    premiumUser == null ? null : premiumUser.uuid()
            );

            var conflictingUser = plugin.getDatabaseProvider().getByUUID(newID);

            if (conflictingUser != null) {
                throw new InvalidCommandArgument(plugin.getMessages().getMessage("kick-occupied-username",
                        "%username%", conflictingUser.getLastNickname()
                ));
            }

            if (premiumUser != null && premiumUser.reliable() && plugin.getConfiguration().get(ConfigurationKeys.AUTO_REGISTER)) {
                if (!premiumUser.name().contentEquals(username)) {
                    throw new InvalidCommandArgument(plugin.getMessages().getMessage("kick-invalid-case-username",
                            "%username%", premiumUser.name()
                    ));
                }
                user = new AuthenticUser(
                        newID,
                        premiumUser.uuid(),
                        null,
                        username,
                        Timestamp.valueOf(LocalDateTime.now()),
                        Timestamp.valueOf(LocalDateTime.now()),
                        null,
                        ip.getHostAddress(),
                        null,
                        null,
                        null
                );
            } else {
                if (premiumUser != null && !premiumUser.reliable()) {
                    plugin.getLogger().warn("The premium data for %s is not reliable, the user may not have the same name capitalization as the premium one. It is not safe to auto-register this user. Switching to offline registration!".formatted(username));
                }
                user = new AuthenticUser(
                        newID,
                        null,
                        null,
                        username,
                        Timestamp.valueOf(LocalDateTime.now()),
                        Timestamp.valueOf(LocalDateTime.now()),
                        null,
                        ip.getHostAddress(),
                        null,
                        null,
                        null
                );
            }

            plugin.getDatabaseProvider().insertUser(user);
        } else return null;

        return user;
    }

    protected BiHolder<Boolean, S> chooseServer(P player, @Nullable String ip, @Nullable User user) {
        var id = platformHandle.getUUIDForPlayer(player);
        var fromFloodgate = plugin.fromFloodgate(id);

        if (fromFloodgate) {
            user = null;
        } else if (user == null) {
            user = plugin.getDatabaseProvider().getByUUID(id);
        }

        if (ip == null) {
            ip = platformHandle.getIP(player);
        }

        if (fromFloodgate || user.autoLoginEnabled() || getSessionStatus(user, ip) == SessionStatus.VALID) {
            return new BiHolder<>(true, plugin.getServerHandler().chooseLobbyServer(user, player, true, false));
        } else {
            return new BiHolder<>(false, plugin.getServerHandler().chooseLimboServer(user, player));
        }
    }

    /**
     * Evaluates the state of a player's auto-login session against the current IP address.
     *
     * @param user the user whose session should be evaluated
     * @param ip   the IP address the player is currently joining from
     * @return {@link SessionStatus#VALID} if the session is active and bound to the given IP,
     * {@link SessionStatus#IP_MISMATCH} if the session is active but was bound to a different IP,
     * or {@link SessionStatus#INVALID} if sessions are disabled or the session has expired.
     */
    protected SessionStatus getSessionStatus(User user, String ip) {
        var debug = plugin.getConfiguration().get(ConfigurationKeys.DEBUG);
        var sessionTime = Duration.ofSeconds(plugin.getConfiguration().get(ConfigurationKeys.SESSION_TIMEOUT));
        if (sessionTime.isZero() || sessionTime.isNegative()) {
            if (debug) plugin.getLogger().debug("Session disabled for %s, session-timeout=%s".formatted(user.getLastNickname(), sessionTime));
            return SessionStatus.INVALID;
        }
        if (user.getLastAuthentication() == null) {
            if (debug) plugin.getLogger().debug("No last-authentication stored for %s, session is invalid".formatted(user.getLastNickname()));
            return SessionStatus.INVALID;
        }
        if (!user.getLastAuthentication().toLocalDateTime().plus(sessionTime).isAfter(LocalDateTime.now())) {
            if (debug) plugin.getLogger().debug("Session expired for %s, last-authentication=%s, session-timeout=%s".formatted(user.getLastNickname(), user.getLastAuthentication(), sessionTime));
            return SessionStatus.INVALID;
        }
        if (!ip.equals(user.getIp())) {
            if (debug) plugin.getLogger().debug("Session IP mismatch for %s, stored-ip=%s, current-ip=%s".formatted(user.getLastNickname(), user.getIp(), ip));
            return SessionStatus.IP_MISMATCH;
        }
        return SessionStatus.VALID;
    }

    protected enum SessionStatus {
        VALID,
        INVALID,
        IP_MISMATCH
    }
}
