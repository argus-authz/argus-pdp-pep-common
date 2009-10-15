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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A base class for Servlets within the authorization service. This class is responsible for properly responding to HTTP
 * methods not supported by the particular endpoint.
 */
public abstract class BaseHttpServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -4322251280891614432L;

    /** {@inheritDoc} */
    protected void doPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doDelete(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doHead(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doOptions(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doPut(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /** {@inheritDoc} */
    protected void doTrace(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", getSupportedMethods());
    }

    /**
     * Gets the HTTP methods supported by this Servlet. This information is used to populate the HTTP "Allow" header.
     * 
     * @return HTTP methods supported by this Servlet
     */
    protected abstract String getSupportedMethods();
}