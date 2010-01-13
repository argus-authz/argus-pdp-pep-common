/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.common.http;

import java.util.List;

import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.BlockingChannelConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.FilterHolder;
import org.mortbay.jetty.servlet.ServletHolder;

/**
 * A Jetty instance that listens on a give port for command requests.
 * 
 * This command starts a separate Jetty instance that binds to 127.0.0.1 on a port given during service construction.
 * Incoming requests are delegated to registered command objects based on their path.
 * 
 * This service also registers a special shutdown command for itself. When the shutdown command, registered at
 * <em>/shutdown</em> is run a set of registered shutdown tasks are executed after which this service is also shutdown.
 */
public class JettyAdminService {

    /** Jetty service within which admin commands run. */
    private Server adminService;

    /** Hostname of the service. */
    private String adminHost;

    /** Port of the service. */
    private int adminPort;

    /** Password required for admin commands. */
    private String adminPassword;

    /** Commands registered with the service. */
    private List<AbstractAdminCommand> adminCommands;

    /** Tasks performed at service shutdown time. */
    private List<Runnable> shutdownTasks;

    /**
     * Constructor.
     * 
     * @param hostname hostname upon which the admin service listens
     * @param port port upon which the admin service listens
     * @param password password required to execute admin commands, may be null if no password is required
     */
    public JettyAdminService(String hostname, int port, String password) {
        adminHost = Strings.safeTrimOrNullString(hostname);
        if (adminHost == null) {
            throw new IllegalArgumentException("Admin service hostname may not be null");
        }

        adminPort = port;
        if (adminPort < 1) {
            throw new IllegalArgumentException("Admin port must be greater than 0");
        }

        if (adminPort > 65535) {
            throw new IllegalArgumentException("Admin port must be less than 65536");
        }

        adminPassword = Strings.safeTrimOrNullString(password);

        adminService = buildAdminService();
        adminCommands = new LazyList<AbstractAdminCommand>();
        shutdownTasks = new LazyList<Runnable>();
    }

    /**
     * Registers a new administration command. New commands may not be registered after the service has been started.
     * 
     * @param command command to register
     */
    public void registerAdminCommand(AbstractAdminCommand command) {
        if (command == null) {
            return;
        }

        if (adminService.isRunning()) {
            throw new IllegalStateException("Admin service is already running");
        }

        for (AbstractAdminCommand adminCommand : adminCommands) {
            if (adminCommand.getCommandPath().equals(command.getCommandPath())) {
                throw new IllegalArgumentException("Another admin command is already registered under the path "
                        + command.getCommandPath());
            }
        }

        adminCommands.add(command);
    }

    /**
     * Registers a task to be run at shutdown time. Tasks will be run in the order they are registered. New tasks may
     * not be registered once the service has been started.
     * 
     * @param task shutdown task to run at service shutdown time
     */
    public void registerShutdownTask(Runnable task) {
        if (task == null) {
            return;
        }

        if (adminService.isRunning()) {
            throw new IllegalStateException("Admin service is already running");
        }

        shutdownTasks.add(task);
    }

    /**
     * Creates and starts the shutdown service.
     */
    public synchronized void start() {
        if (adminService.isRunning()) {
            throw new IllegalStateException("Admin service is already running");
        }

        Context commandContext = new Context(adminService, "/", false, false);

        adminCommands.add(buildShutdownCommand());

        ServletHolder servletHolder;
        for (AbstractAdminCommand command : adminCommands) {
            servletHolder = new ServletHolder(command);
            commandContext.addServlet(servletHolder, command.getCommandPath());
        }

        if (adminPassword != null) {
            FilterHolder passwordFiler = new FilterHolder(new PasswordProtectFilter(adminPassword));
            commandContext.addFilter(passwordFiler, "/*", Handler.REQUEST);
        }

        JettyRunThread shutdownServiceRunThread = new JettyRunThread(adminService);
        shutdownServiceRunThread.start();
    }

    /**
     * Builds the Jetty server that will receive admin requests.
     * 
     * @return Jetty server that will receive admin requests
     */
    protected Server buildAdminService() {
        adminService = new Server();
        adminService.setSendServerVersion(false);
        adminService.setSendDateHeader(false);

        BlockingChannelConnector connector = new BlockingChannelConnector();
        connector.setHost(adminHost);
        connector.setPort(adminPort);
        adminService.setConnectors(new Connector[] { connector });

        return adminService;
    }

    /**
     * Builds an {@link AbstractAdminCommand} which shutdowns this admin service.
     * 
     * @return the shutdown command
     */
    protected AbstractAdminCommand buildShutdownCommand() {
        List<Runnable> augmentedShutdownTasks = new LazyList<Runnable>();
        augmentedShutdownTasks.addAll(shutdownTasks);
        augmentedShutdownTasks.add(new JettyShutdownTask(adminService));

        return new ShutdownCommand(augmentedShutdownTasks);
    }
}