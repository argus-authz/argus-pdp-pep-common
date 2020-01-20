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

import org.glite.authz.common.util.Strings;
import org.opensaml.ws.soap.client.SOAPClient;

/**
 * A builder of {@link AbstractServiceConfiguration} objects.
 * 
 * @param <ConfigType> the concrete type of configuration object created
 */
public abstract class AbstractServiceConfigurationBuilder<ConfigType extends AbstractServiceConfiguration> extends
        AbstractConfigurationBuilder<ConfigType> {

    /** The entity ID for the service. */
    private String entityId;

    /** Hostname upon which the service listens. */
    private String hostname;

    /** Port number upon which the service listens. */
    private int port;

    /** Whether SSL is enabled on the service port. */
    private boolean sslEnabled;

    /** TLS protocol used when SSL is enabled. */
    private String tlsProtocol;

    /** Whether client is required to authenticate with a client certificate. */
    private boolean clientCertAuthRequired;

    /** Hostname upon which the admin service listens. */
    private String adminHost;

    /** Port number upon which the admin service listens. */
    private int adminPort;

    /** Password required for admin commands. */
    private String adminPassword;

    /** Max number of requests that will be queued if all PDP processing threads are busy. */
    private int maxRequestQueueSize;

    /** SOAP client used to communicate with the PAP. */
    private SOAPClient soapClient;

    /** Constructor. */
    protected AbstractServiceConfigurationBuilder() {
        entityId = null;
        hostname = null;
        port = 0;
        sslEnabled = false;
        clientCertAuthRequired = false;
        adminHost = null;
        adminPort = 0;
        adminPassword = null;
        maxRequestQueueSize = 0;
        soapClient = null;
    }

    /**
     * Constructor that creates a builder whose settings are initialized with the properties from the given prototype
     * configuration.
     * 
     * @param prototype a prototypical configuration upon which this builder will be based
     */
    protected AbstractServiceConfigurationBuilder(AbstractServiceConfiguration prototype) {
        super(prototype);

        entityId = prototype.getEntityId();
        hostname = prototype.getHostname();
        port = prototype.getPort();
        sslEnabled = prototype.isSslEnabled();
        clientCertAuthRequired = prototype.isClientCertAuthRequired();
        adminHost = prototype.getAdminHost();
        adminPort = prototype.getAdminPort();
        adminPassword = prototype.getAdminPassword();
        maxRequestQueueSize = prototype.getMaxRequestQueueSize();
        soapClient = prototype.getSOAPClient();
    }

    /**
     * Gets the Entity ID of the service.
     * 
     * @return entity ID of the service
     */
    public String getEntityId() {
        return entityId;
    }

    /**
     * Gets the host to which the service will bind.
     * 
     * @return host to which the sevice will bind
     */
    public String getHost() {
        return hostname;
    }

    /**
     * Gets the max number of requests the daemon will enqueue.
     * 
     * @return max number of requests the daemon will enqueue
     */
    public int getMaxRequestQueueSize() {
        return maxRequestQueueSize;
    }

    /**
     * Gets the port upon which the daemon will listen.
     * 
     * @return port upon which the daemon will listen
     */
    public int getPort() {
        return port;
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
     * @return port number upon which the shuadmintdown service listens
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
     * Gets the SOAP client used by the service to communicate with other services.
     * 
     * @return SOAP client used by the service to communicate with other services
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
        return sslEnabled;
    }

    /**
     * Gets TLS protocol used when SSL is enabled.
     * 
     * @return TLS protocol used when SSL is enabled
     */
    public String getTlsProtocol() {
        return tlsProtocol;
    }

    /**
     * Gets whether client certificate authentication is required when a client is connecting.
     * 
     * @return whether client certificate authentication is required
     */
    public boolean isClientCertAuthRequired() {
        return clientCertAuthRequired;
    }

    /** {@inheritDoc} */
    protected void populateConfiguration(ConfigType config) {
        super.populateConfiguration(config);
        config.setEntityId(entityId);
        config.setHostname(hostname);
        config.setPort(port);
        config.setSslEnabled(sslEnabled);
        config.setTlsProtocol(tlsProtocol);
        config.setClientCertAuthRequired(clientCertAuthRequired);
        config.setAdminHost(adminHost);
        config.setAdminPort(adminPort);
        config.setAdminPassword(adminPassword);
        config.setMaxRequestQueueSize(maxRequestQueueSize);
        config.setSOAPClient(soapClient);
    }

    /**
     * Sets the Entity ID of the service.
     * 
     * @param id Entity ID of the service
     */
    public void setEntityId(String id) {
        entityId = Strings.safeTrimOrNullString(id);
    }

    /**
     * Sets the hostname or IP address upon which the service will listen.
     * 
     * @param newHost hostname or IP address upon which the service will listen
     */
    public void setHost(String newHost) {
        if (Strings.isEmpty(newHost)) {
            throw new IllegalArgumentException("Host may not be null or empty");
        }
        hostname = newHost;
    }

    /**
     * Sets the max number of requests the service will enqueue.
     * 
     * @param max max number of requests the service will enqueue
     */
    public void setMaxRequestQueueSize(int max) {
        maxRequestQueueSize = max;
    }

    /**
     * Sets the port upon which the service will listen.
     * 
     * @param newPort port upon which the service will listen
     */
    public void setPort(int newPort) {
        port = newPort;
    }

    /**
     * Sets the host upon which the admin service listens.
     * 
     * @param host host upon which the admin service listens
     */
    public void setAdminHost(String host) {
        adminHost = host;
    }

    /**
     * Sets the port number upon which the admin service listens.
     * 
     * @param newPort port number upon which the admin service listens
     */
    public void setAdminPort(int newPort) {
        adminPort = newPort;
    }

    /**
     * Sets the password required for admin commands.
     * 
     * @param password password required for admin commands
     */
    public void setAdminPassword(String password) {
        adminPassword = password;
    }

    /**
     * Sets the SOAP client used by the service to communicate with other services.
     * 
     * @param client SOAP client used by the service to communicate with other services
     */
    public void setSoapClient(SOAPClient client) {
        if (client == null) {
            throw new IllegalArgumentException("SOAP client may not be null");
        }
        soapClient = client;
    }

    /**
     * Sets whether SSL is enabled on the service port.
     * 
     * @param enabled whether SSL is enabled on the service port
     */
    public void setSslEnabled(boolean enabled) {
        sslEnabled = enabled;
    }

    /**
     * Sets TLS protocol used when SSL is enabled.
     * 
     * @param TLS protocol used when SSL is enabled
     */
    public void setTlsProtocol(String protocol) {
        tlsProtocol = protocol;
    }

    /**
     * Sets whether client certificate authentication is required when a client is connecting.
     * 
     * @param required whether client certificate authentication is required
     */
    public void setClientCertAuthRequired(boolean required) {
        clientCertAuthRequired = required;
    }
}