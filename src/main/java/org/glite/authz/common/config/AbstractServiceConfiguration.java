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

package org.glite.authz.common.config;

import org.glite.authz.common.ServiceMetrics;
import org.opensaml.ws.soap.client.SOAPClient;

/** Base class for service configurations. */
public abstract class AbstractServiceConfiguration extends AbstractConfiguration {

    /** Metrics for this service. */
    private ServiceMetrics serviceMetrics;

    /** The entity ID for the service. */
    private String entityId;

    /** Hostname upon which the service listens. */
    private String hostname;

    /** Port number upon which the service listens. */
    private int port;

    /** Whether SSL is enabled on the service port. */
    private Boolean sslEnabled;

    /** Whether client is required to authenticate with a client certificate. */
    private Boolean clientCertAuthRequired;

    /** Hostname upon which the admin service listens. */
    private String adminHost;

    /** Port number upon which the admin service listens. */
    private int adminPort;

    /** Password required for admin commands. */
    private String adminPassword;

    /** Max number of requests that will be queued if all processing threads are busy. */
    private int maxRequestQueueSize;

    /** SOAP client used to communicate with other services. */
    private SOAPClient soapClient;

    /**
     * Constructor.
     * 
     * @param metrics metrics container for this store
     */
    protected AbstractServiceConfiguration(ServiceMetrics metrics) {
        super();
        serviceMetrics = metrics;
        hostname = null;
        port = 0;
        sslEnabled = null;
        adminHost = null;
        adminPort = 0;
        adminPassword = null;
        maxRequestQueueSize = 0;
        soapClient = null;
    }

    /**
     * Gets the entity ID of the service.
     * 
     * @return entity ID of the service
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * Gets the hostname upon which the service listens.
     * 
     * @return hostname upon which the service listens
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Gets whether client certificate authentication is required for connecting clients.
     * 
     * @return whether client certificate authentication is required
     */
    public boolean isClientCertAuthRequired() {
        return clientCertAuthRequired == null ? false : clientCertAuthRequired;
    }

    /**
     * Gets the maximum number of requests the will queue up if all of its request processing threads are busy.
     * 
     * @return maximum number of requests the will queue up if all of its request processing threads are busy
     */
    public int getMaxRequestQueueSize() {
        return maxRequestQueueSize;
    }

    /**
     * Gets the port number upon which the service listens.
     * 
     * @return the port number upon which the service listens
     */
    public int getPort() {
        return port;
    }

    /**
     * Gets the metrics for this service.
     * 
     * @return metrics for this service
     */
    public ServiceMetrics getServiceMetrics() {
        return serviceMetrics;
    }

    /**
     * Gets the host upon which the admin service listens.
     * 
     * @return host upon which the admin service listens
     */
    public String getAdminHost() {
        return adminHost;
    }

    /**
     * Gets the port number upon which the admin service listens.
     * 
     * @return port number upon which the admin service listens
     */
    public int getAdminPort() {
        return adminPort;
    }

    /**
     * Gets the password required for admin commands.
     * 
     * @return password required for admin commands
     */
    public String getAdminPassword() {
        return adminPassword;
    }

    /**
     * Gets the SOAP client used to communicate with other services.
     * 
     * @return SOAP client used to communicate with other services
     */
    public SOAPClient getSOAPClient() {
        return soapClient;
    }

    /**
     * Gets whether SSL is enabled on the service port.
     * 
     * @return whether SSL is enabled on the service port
     */
    public boolean isSslEnabled() {
        return sslEnabled == null ? false : sslEnabled;
    }

    /**
     * Sets the entity ID of the service.
     * 
     * @param id entity ID of the service
     */
    protected final synchronized void setEntityId(String id) {
        if (entityId != null) {
            throw new IllegalStateException("Entity ID has already been set, it may not be changed");
        }
        entityId = id;
    }

    /**
     * Sets the hostname upon which the service listens.
     * 
     * @param newHost hostname upon which the service listens
     */
    protected final synchronized void setHostname(String newHost) {
        if (hostname != null) {
            throw new IllegalArgumentException("Hostname has already been set, it may be changed");
        }
        hostname = newHost;
    }

    /**
     * Sets whether client certificate authentication is required of connecting clients.
     * 
     * @param required whether client certificate authentication is required
     */
    protected final synchronized void setClientCertAuthRequired(boolean required) {
        if (clientCertAuthRequired != null) {
            throw new IllegalStateException(
                    "Client cert authentication requirement has already been set, it may not be changed");
        }
        clientCertAuthRequired = required;
    }

    /**
     * Sets the maximum number of requests the will queue up if all of its request processing threads are busy.
     * 
     * @param max maximum number of requests the will queue up if all of its request processing threads are busy
     */
    protected final synchronized void setMaxRequestQueueSize(int max) {
        if (maxRequestQueueSize != 0) {
            throw new IllegalStateException("Max request size has already been set, it may not be changed");
        }
        maxRequestQueueSize = max;
    }

    /**
     * Sets the port number upon which the service listens.
     * 
     * @param newPort number upon which the service listens
     */
    protected final synchronized void setPort(int newPort) {
        if (port != 0) {
            throw new IllegalStateException("Service port number has already been set, it may not be changed");
        }
        port = newPort;
    }

    /**
     * Sets the hostname upon which the admin service listens.
     * 
     * @param host hostname upon which the admin service listens
     */
    protected final synchronized void setAdminHost(String host) {
        if (adminHost != null) {
            throw new IllegalStateException("Admin hostname has alrady been set, it may not be changed.");
        }
        adminHost = host;
    }

    /**
     * Sets the port number upon which the admin service listens.
     * 
     * @param port port number upon which the admin service listens
     */
    protected final synchronized void setAdminPort(int port) {
        if (adminPort != 0) {
            throw new IllegalStateException("Admin service port has already been set, it may not be changed");
        }

        adminPort = port;
    }

    /**
     * Sets the password required for admin commands.
     * 
     * @param password the password required for admin commands
     */
    protected final synchronized void setAdminPassword(String password) {
        if (adminPassword != null) {
            throw new IllegalStateException("Admin password has alrady been set, it may not be changed.");
        }

        adminPassword = password;
    }

    /**
     * Sets the SOAP client used to communicate with other services.
     * 
     * @param client SOAP client used to communicate with other services
     */
    protected final synchronized void setSOAPClient(SOAPClient client) {
        if (soapClient != null) {
            throw new IllegalStateException("SOAP client has already been set, it may not be changed");
        }
        soapClient = client;
    }

    /**
     * Sets whether SSL is enabled on the service port.
     * 
     * @param enabled whether SSL is enabled on the service port
     */
    protected final synchronized void setSslEnabled(boolean enabled) {
        if (sslEnabled != null) {
            throw new IllegalStateException(
                    "SSL enablement of service port has already been set, it may not be changed");
        }
        sslEnabled = enabled;
    }
}