/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common;

import xyz.kyngs.librelogin.api.Logger;

import java.util.function.Supplier;
import java.util.logging.Level;

public class JavaUtilLogger implements Logger {

    private final java.util.logging.Logger jul;
    private final Supplier<Boolean> debug;

    public JavaUtilLogger(java.util.logging.Logger jul, Supplier<Boolean> debug) {
        this.jul = jul;
        this.debug = debug;
    }

    @Override
    public void info(String message) {
        jul.info(message);
    }

    @Override
    public void info(String message, Throwable throwable) {
        jul.log(Level.INFO, message, throwable);
    }

    @Override
    public void warn(String message) {
        jul.warning(message);
    }

    @Override
    public void warn(String message, Throwable throwable) {
        jul.log(Level.WARNING, message, throwable);
    }

    @Override
    public void error(String message) {
        jul.severe(message);
    }

    @Override
    public void error(String message, Throwable throwable) {
        jul.log(Level.SEVERE, message, throwable);
    }

    @Override
    public void debug(String message) {
        if (debug.get()) {
            jul.info("[DEBUG] " + message);
        }
    }

    @Override
    public void debug(String message, Throwable throwable) {
        if (debug.get()) {
            jul.log(Level.INFO, "[DEBUG] " + message, throwable);
        }
    }
}