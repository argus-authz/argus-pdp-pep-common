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

package org.glite.authz.common.config;

import org.opensaml.ws.soap.client.SOAPClient;

/** Base class for service configurations. */
public abstract class AbstractServiceConfiguration extends AbstractConfiguration {

    /** The entity ID for the PDP service. */
    private String entityId;

    /** Hostname upon which the PDP service listens. */
    private String hostname;

    /** Port number upon which the PDP service listens. */
    private int port;

    /** Port number upon which the PDP shutdown service listens. */
    private int shutdownPort;

    /** Max number of requests that will be queued if all PDP processing threads are busy. */
    private int maxRequestQueueSize;

    /** SOAP client used to communicate with the PAP. */
    private SOAPClient soapClient;

    /** Constructor. */
    protected AbstractServiceConfiguration() {
        super();
        hostname = null;
        port = 0;
        shutdownPort = 0;
        maxRequestQueueSize = 0;
        soapClient = null;
    }

    /**
     * Gets the entity ID of the PDP service.
     * 
     * @return entity ID of the PDP service
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * Gets the hostname upon which the PDP service listens.
     * 
     * @return hostname upon which the PDP service listens
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Gets the maximum number of requests the PDP will queue up if all of its request processing threads are busy.
     * 
     * @return maximum number of requests the PDP will queue up if all of its request processing threads are busy
     */
    public int getMaxRequestQueueSize() {
        return maxRequestQueueSize;
    }

    /**
     * Gets the port number upon which the PDP service listens.
     * 
     * @return the port number upon which the PDP service listens
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets the port number upon which the PDP shutdown service listens.
     * 
     * @return port number upon which the PDP shutdown service listens
     */
    public int getShutdownPort() {
        return shutdownPort;
    }

    /**
     * Gets the SOAP client used to communicate with the PAP.
     * 
     * @return SOAP client used to communicate with the PAP
     */
    public SOAPClient getSOAPClient() {
        return soapClient;
    }

    /**
     * Sets the entity ID of the PDP service.
     * 
     * @param id entity ID of the PDP service
     */
    protected synchronized final void setEntityId(String id) {
        if (entityId != null) {
            throw new IllegalStateException("Entity ID has already been set, it may not be changed");
        }
        entityId = id;
    }

    /**
     * Sets the hostname upon which the PDP service listens.
     * 
     * @param newHost hostname upon which the PDP service listens
     */
    protected synchronized final void setHostname(String newHost) {
        if (hostname != null) {
            throw new IllegalArgumentException("Hostname has already been set, it may be changed");
        }
        hostname = newHost;
    }

    /**
     * Sets the maximum number of requests the PDP will queue up if all of its request processing threads are busy.
     * 
     * @param max maximum number of requests the PDP will queue up if all of its request processing threads are busy
     */
    protected synchronized final void setMaxRequestQueueSize(int max) {
        if (maxRequestQueueSize != 0) {
            throw new IllegalStateException("Max request size has already been set, it may not be changed");
        }
        maxRequestQueueSize = max;
    }

    /**
     * Sets the port number upon which the PDP service listens.
     * 
     * @param newPort number upon which the PDP service listens
     */
    protected synchronized final void setPort(int newPort) {
        if (port != 0) {
            throw new IllegalStateException("Service port number has already been set, it may not be changed");
        }
        port = newPort;
    }

    /**
     * Sets the port number upon which the PDP shutdown service listens.
     * 
     * @param port the shutdownPort to set
     */
    protected synchronized final void setShutdownPort(int port) {
        if (shutdownPort != 0) {
            throw new IllegalStateException("Shutdown service port has already been set, it may not be changed");
        }

        shutdownPort = port;
    }

    /**
     * Sets the SOAP client used to communicate with the PAP.
     * 
     * @param client SOAP client used to communicate with the PAP
     */
    protected synchronized final void setSOAPClient(SOAPClient client) {
        if (soapClient != null) {
            throw new IllegalStateException("SOAP client has already been set, it may not be changed");
        }
        soapClient = client;
    }
}