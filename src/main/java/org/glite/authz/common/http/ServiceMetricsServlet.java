/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

/**
 * Service metrics servlet -> /status
 */
public class ServiceMetricsServlet extends BaseHttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID= -35456601036224136L;

    /** Configuration for the service. */
    private ServiceMetrics serviceMetrics_;

    /**
     * Constructor
     * 
     * @param serviceMetrics
     *            the service metrics to use for the status
     */
    public ServiceMetricsServlet(ServiceMetrics serviceMetrics) {
        if (serviceMetrics == null) {
            throw new IllegalArgumentException("Service metrics may not be null");
        }
        serviceMetrics_= serviceMetrics;
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "GET";
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/plain");
        serviceMetrics_.printServiceMetrics(resp.getWriter());
    }
}
