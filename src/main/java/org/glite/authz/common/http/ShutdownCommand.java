/*
 * Copyright 2010 Members of the EGEE Collaboration.
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

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Commands used to issue a set of tasks to be executed when a service is shut down. */
public class ShutdownCommand extends AbstractAdminCommand {

    /** Serial version UID. */
    private static final long serialVersionUID = 8098511780458295197L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ShutdownCommand.class);

    /** Background thread used to shut everything down. */
    private Thread shutdownThread;

    /**
     * Constructor.
     * 
     * @param shutdownTasks tasks that must be executed, in order, when shutting the service down
     */
    public ShutdownCommand(final List<Runnable> shutdownTasks) {
        super("shutdown");

        if (shutdownTasks == null || shutdownTasks.isEmpty()) {
            return;
        }

        shutdownThread = new Thread() {
            public void run() {
                for (Runnable shutdownTask : shutdownTasks) {
                    shutdownTask.run();
                }
            };
        };
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.getWriter().write("ok");
        resp.flushBuffer();
        log.info("Service shutting down");
        if (shutdownThread != null) {
            shutdownThread.start();
        }
        return;
    }
}