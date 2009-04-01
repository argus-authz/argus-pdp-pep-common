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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.config.AbstractServiceConfiguration;

/** Servlet that prints the metrics available from the {@link AbstractServiceConfiguration#getServiceMetrics()} */
public class ServiceStatusServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 7123520396106212362L;
    
    /** Configuration for the service. */
    private AbstractServiceConfiguration serviceConfig;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        serviceConfig = (AbstractServiceConfiguration) getServletContext().getAttribute(
                AbstractServiceConfiguration.BINDING_NAME);
        if (serviceConfig == null) {
            throw new ServletException("Unable to initialize, no service configuration available in servlet context");
        }
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.setContentType("text/plain");
        serviceConfig.getServiceMetrics().printServiceMetrics(httpResponse.getWriter());
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "GET";
    }
}