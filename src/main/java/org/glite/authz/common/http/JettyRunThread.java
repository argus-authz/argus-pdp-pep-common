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

import org.mortbay.jetty.Server;

/** A thread that spawns a Jetty {@link Server} instance. */
public class JettyRunThread extends Thread {

    /** Jetty server to start. */
    private Server httpServer;

    /**
     * Constructor.
     * 
     * @param server Jetty server to start
     */
    public JettyRunThread(Server server) {
        httpServer = server;
    }

    /** {@inheritDoc} */
    public void run() {
        try {
            httpServer.start();
            httpServer.join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}