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

package org.glite.authz.common.logging;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.xml.util.DatatypeHelper;

/** Data object for generating service access logs. */
public class AccessLogEntry {
    
    /** Time the request was made. */
    private long requestTime;

    /** Hostname or IP address of the remote host. */
    private String remoteHost;

    /** Hostname or IP address of the server. */
    private String serverHost;

    /** Port the request came in on. */
    private int serverPort;

    /** Path of the request. */
    private String requestPath;

    /**
     * Constructor.
     * 
     * @param request the request
     */
    public AccessLogEntry(HttpServletRequest request) {
        requestTime = new DateTime().toDateTimeISO().getMillis();
        remoteHost = request.getRemoteHost();
        serverHost = request.getServerName();
        serverPort = request.getServerPort();
        
        String servletPath = request.getServletPath();
        if (request.getPathInfo() == null) {
            requestPath = servletPath;
        } else {
            requestPath = servletPath + request.getPathInfo();
        }
    }

    /**
     * Constructor.
     * 
     * @param remote the remote client host name or IP
     * @param host the servers host name or IP
     * @param port the servers port number
     * @param path the request path information minus the servlet context information
     */
    public AccessLogEntry(String remote, String host, int port, String path) {
        requestTime = new DateTime().toDateTimeISO().getMillis();
        remoteHost = DatatypeHelper.safeTrimOrNullString(remote);
        serverHost = DatatypeHelper.safeTrimOrNullString(host);
        serverPort = port;
        requestPath = DatatypeHelper.safeTrimOrNullString(path);
    }

    /**
     * Gets the remote client host or IP address.
     * 
     * @return remote client host or IP address
     */
    public String getRemoteHost() {
        return remoteHost;
    }

    /**
     * Gets the request path without servlet context information.
     * 
     * @return request path without servlet context information
     */
    public String getRequestPath() {
        return requestPath;
    }
    
    /**
     * Gets the time the request was made.
     * 
     * @return time the request was made
     */
    public long getRequestTime(){
        return requestTime;
    }

    /**
     * Gets the server's host name or IP address.
     * 
     * @return server's host name or IP address
     */
    public String getServerHost() {
        return serverHost;
    }

    /**
     * Gets the server's port number.
     * 
     * @return server's port number
     */
    public int getServerPort() {
        return serverPort;
    }
    
    /** {@inheritDoc} */
    public String toString() {
        StringBuilder entryString = new StringBuilder();

        entryString.append(getRequestTime());
        entryString.append("|");

        entryString.append(getRemoteHost());
        entryString.append("|");

        entryString.append(getServerHost());
        entryString.append(":");
        entryString.append(getServerPort());
        entryString.append("|");

        entryString.append(getRequestPath());
        entryString.append("|");

        return entryString.toString();
    }
}