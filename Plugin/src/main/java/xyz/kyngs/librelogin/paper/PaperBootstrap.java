/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.paper;

import net.byteflux.libby.BukkitLibraryManager;
import net.byteflux.libby.LibraryManager;
import net.byteflux.libby.PaperLibraryManager;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.bukkit.generator.ChunkGenerator;
import org.bukkit.plugin.java.JavaPlugin;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import xyz.kyngs.librelogin.api.provider.LibreLoginProvider;

public class PaperBootstrap extends JavaPlugin implements LibreLoginProvider<Player, World> {

    private PaperLibreLogin libreLogin;

    @Override
    public @Nullable ChunkGenerator getDefaultWorldGenerator(@NotNull String worldName, @Nullable String id) {
        return id == null ?
                null
                : id.equals("void") ? new VoidWorldGenerator() : null;
    }

    @Override
    public void onLoad() {
        getLogger().info("Analyzing server setup...");

        LibraryManager libraryManager;

        try {
            Class.forName("io.papermc.paper.plugin.entrypoint.classloader.PaperPluginClassLoader");
            libraryManager = new PaperLibraryManager(this);
        } catch (ClassNotFoundException e) {
            libraryManager = new BukkitLibraryManager(this);
        }

        getLogger().info("Loading libraries...");

        try {
            libraryManager.configureFromJSON();
        } catch (Exception e) {
            getLogger().log(java.util.logging.Level.SEVERE, "Failed to load libraries, stopping server to prevent damage", e);
            stopServer();
        }

        try {
            Class.forName("net.kyori.adventure.audience.Audience");
        } catch (ClassNotFoundException e) {
            unsupportedSetup();
        }

        getLogger().info("Detected a supported server distribution - " + getServer().getName() + " " + getServer().getVersion());

        libreLogin = new PaperLibreLogin(this);
    }

    @Override
    public void onEnable() {
        getLogger().info("Bootstrapping LibreLogin...");
        libreLogin.enable();
    }

    private void unsupportedSetup() {
        getLogger().severe("***********************************************************");

        getLogger().severe("Could not load the Adventure library. Please make sure the server has internet access so LibreLogin can download its libraries.");

        getLogger().severe("***********************************************************");

        stopServer();
    }

    private void stopServer() {
        try {
            Thread.sleep(5000);
        } catch (InterruptedException ignored) {
        }

        System.exit(1);
    }

    @Override
    public void onDisable() {
        libreLogin.disable();
    }

    @Override
    public PaperLibreLogin getLibreLogin() {
        return libreLogin;
    }

    protected void disable() {
        setEnabled(false);
    }

}
