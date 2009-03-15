/*
 * Copyright 2009 EGEE Collaboration
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.BlockingChannelConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;

/**
 * A Jetty instance that listens on a give port for a request to the URL path <em>/shutdown</em>.
 * 
 * This command starts a separate Jetty instance that binds to 127.0.0.1 on a port given during service construction.
 * When a GET request is received a thread is spawned that runs each given shutdown command in turn. Finally, after all
 * commands have been run, the created shutdown service is stopped as well. The shutdown process occurs asynchronously
 * and does NOT block the return of the GET request.
 * 
 * Additionally, the same shutdown procedure is bound as a JVM shutdown hook in the event that the process is terminated in that fashion.
 */
public class JettyShutdownService {

    /**
     * Creates and starts the shutdown service.
     * 
     * @param shutdownPort port on which the service will listen
     * @param shutdownCommands list of commands to run at shutdown time
     */
    public static void startJettyShutdownService(int shutdownPort, List<Runnable> shutdownCommands) {

        final Server shutdownService = new Server();
        shutdownService.setSendServerVersion(false);
        shutdownService.setSendDateHeader(false);

        final Thread shutdownCommandThread = buildServiceShutdownThread(shutdownService, shutdownCommands);

        BlockingChannelConnector connector = new BlockingChannelConnector();
        connector.setHost("127.0.0.1");
        connector.setPort(shutdownPort);
        shutdownService.setConnectors(new Connector[] { connector });

        Context servletContext = new Context(shutdownService, "/", false, false);
        servletContext.setDisplayName("Shutdown Controller");

        ServletHolder shutdownServlet = new ServletHolder(new HttpServlet() {
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
                resp.setStatus(HttpServletResponse.SC_OK);
                resp.getWriter().write("ok");
                resp.flushBuffer();
                shutdownCommandThread.start();
                return;
            }
        });
        servletContext.addServlet(shutdownServlet, "/shutdown");

        JettyRunThread shutdownServiceRunThread = new JettyRunThread(shutdownService);
        shutdownServiceRunThread.start();
    }

    /**
     * Creates the thread that run in order to shutdown everything.  This will create a new shutdown command, added to the end of the given list,
     * that will shutdown the shutdown service currently being created.
     * 
     * @param shutdownService the shutdown service being created
     * @param commands the shutdown commands to run before stopping the shutdown service
     * 
     * @return the shutdown thread
     */
    private static Thread buildServiceShutdownThread(final Server shutdownService, List<Runnable> commands) {
        final Runnable shutdownShutdownServiceCommand = new JettyShutdownCommand(shutdownService);

        final List<Runnable> shutdownCommands;
        if (commands == null || commands.isEmpty()) {
            shutdownCommands = Collections.singletonList(shutdownShutdownServiceCommand);
        } else {
            shutdownCommands = new ArrayList<Runnable>(commands);
            shutdownCommands.add(shutdownShutdownServiceCommand);
        }

        final Thread shutdownCommandThread = new Thread() {
            public void run() {
                for (Runnable shutdownCommand : shutdownCommands) {
                    shutdownCommand.run();
                }
            }
        };

        Runtime.getRuntime().addShutdownHook(new Thread(shutdownCommandThread));
        return shutdownCommandThread;
    }
}