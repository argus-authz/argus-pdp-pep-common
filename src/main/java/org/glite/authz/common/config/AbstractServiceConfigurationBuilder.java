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

package org.glite.authz.common.config;

import org.glite.authz.common.obligation.ObligationService;
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

    /** Port number upon which the shutdown service listens. */
    private int shutdownPort;

    /** Max number of requests that will be queued if all PDP processing threads are busy. */
    private int maxRequestQueueSize;

    /** SOAP client used to communicate with the PAP. */
    private SOAPClient soapClient;

    /** Obligation service used by PEP. */
    private ObligationService obligationService;

    /** Constructor. */
    protected AbstractServiceConfigurationBuilder() {
        entityId = null;
        hostname = null;
        port = 0;
        shutdownPort = 0;
        maxRequestQueueSize = 0;
        soapClient = null;
        obligationService = new ObligationService();
    }
    
    /**
     * Constructor that creates a builder whose settings are initialized with the properties from the given prototype
     * configuration.
     * 
     * @param prototype
     */
    protected AbstractServiceConfigurationBuilder(AbstractServiceConfiguration prototype) {
        super(prototype);

        entityId = prototype.getEntityId();
        hostname = prototype.getHostname();
        port = prototype.getPort();
        sslEnabled = prototype.isSslEnabled();
        shutdownPort = prototype.getShutdownPort();
        maxRequestQueueSize = prototype.getMaxRequestQueueSize();
        soapClient = prototype.getSOAPClient();
        obligationService = prototype.getObligationService();
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
     * Gets the service used to handle obligations.
     * 
     * @return service used to handle obligations
     */
    public ObligationService getObligationService() {
        return obligationService;
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
     * Gets the port number upon which the shutdown service listens.
     * 
     * @return port number upon which the shutdown service listens
     */
    public int getShutdownPort() {
        return shutdownPort;
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

    /** {@inheritDoc} */
    protected void populateConfiguration(ConfigType config) {
        super.populateConfiguration(config);
        config.setEntityId(entityId);
        config.setHostname(hostname);
        config.setPort(port);
        config.setSslEnabled(sslEnabled);
        config.setShutdownPort(shutdownPort);
        config.setMaxRequestQueueSize(maxRequestQueueSize);
        config.setSOAPClient(soapClient);
        config.setObligationService(obligationService);
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
     * Sets the service used to handle obligations.
     * 
     * @param service service used to handle obligations
     */
    public void setObligationService(ObligationService service) {
        obligationService = service;
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
     * Sets the port number upon which the shutdown service listens.
     * 
     * @param port port number upon which the shutdown service listens
     */
    public void setShutdownPort(int port) {
        shutdownPort = port;
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
}