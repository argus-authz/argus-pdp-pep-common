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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.ServiceMetrics;

/** A command that prints out {@link ServiceMetrics}. */
public class StatusCommand extends AbstractAdminCommand {

    /** Serial version UID. */
    private static final long serialVersionUID = 8712398619509925570L;
    
    /** Configuration for the service. */
    private ServiceMetrics serviceMetrics;

    /**
     * Constructor.
     * 
     * @param metrics metrics to be printed by this command
     */
    public StatusCommand(ServiceMetrics metrics) {
        super("/status");

        if (metrics == null) {
            throw new IllegalArgumentException("Service metrics may not be null");
        }
        serviceMetrics = metrics;
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/plain");
        serviceMetrics.printServiceMetrics(resp.getWriter());
    }
}