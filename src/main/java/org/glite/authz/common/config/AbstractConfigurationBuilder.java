/*
 * Copyright 2008 EGEE Collaboration
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

import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.X509KeyManager;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.obligation.ObligationService;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;
import org.glite.voms.PKIStore;

/**
 * Base class for builders of {@link AbstractConfiguration} objects.
 * 
 * @param <ConfigType> the type of configuration object built
 */
@NotThreadSafe
public abstract class AbstractConfigurationBuilder<ConfigType extends AbstractConfiguration> {

    /** Logging configuration file path. */
    private String loggingConfigFilePath;

    /** A key manager containing the service's credential. */
    private X509KeyManager keyManager;

    /** Store for X.509 store material. */
    private PKIStore trustMaterialStore;

    /** Maximum number of concurrent connections that may be in-process at one time. */
    private int maxConnections;

    /** Connection timeout in milliseconds. */
    private int connectionTimeout;

    /** Size of the buffer, in bytes, used when receiving data. */
    private int receiveBufferSize;

    /** Size of the buffer, in bytes, used when sending data. */
    private int sendBufferSize;

    /** Registered policy information points. */
    private List<PolicyInformationPoint> policyInformationPoints;

    /** Service used to handler obligations. */
    private ObligationService obligationService;

    /** Constructor. */
    protected AbstractConfigurationBuilder() {
        maxConnections = 0;
        connectionTimeout = 0;
        receiveBufferSize = 0;
        sendBufferSize = 0;
        keyManager = null;
        trustMaterialStore = null;
        policyInformationPoints = new ArrayList<PolicyInformationPoint>();
        obligationService = new ObligationService();
    }

    /**
     * Constructor thats creates a builder factory with the same settings as the given prototype configuration.
     * 
     * @param prototype the prototype configuration whose values will be used to initialize this builder
     */
    protected AbstractConfigurationBuilder(AbstractConfiguration prototype) {
        maxConnections = prototype.getMaxRequests();
        connectionTimeout = prototype.getConnectionTimeout();
        receiveBufferSize = prototype.getReceiveBufferSize();
        sendBufferSize = prototype.getSendBufferSize();

        if (prototype.getPolicyInformationPoints() != null) {
            policyInformationPoints = new ArrayList<PolicyInformationPoint>(prototype.getPolicyInformationPoints());
        } else {
            policyInformationPoints = new ArrayList<PolicyInformationPoint>();
        }
        obligationService = prototype.getObligationService();
    }

    /**
     * Builds the configuration represented by the current set properties. Please note that configuration builders are
     * <strong>not</strong> threadsafe.  So care should be taken that another thread does not change properties while 
     * the configuration is being built.
     * 
     * @return the constructed configuration
     */
    public abstract ConfigType build();

    /**
     * Gets the connection socket timeout, in milliseconds.
     * 
     * @return connection socket timeout, in milliseconds
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Gets the path to the logging file configuration location.
     * 
     * @return path to the logging file configuration location
     */
    public String getLoggingConfigFilePath() {
        return loggingConfigFilePath;
    }

    /**
     * Gets the maximum number of concurrent connections that may be in-process at one time.
     * 
     * @return maximum number of concurrent connections that may be in-process at one time
     */
    public int getMaxConnections() {
        return maxConnections;
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
     * Gets the list of registered PIPs.
     * 
     * @return list of registered PIPs
     */
    public List<PolicyInformationPoint> getPIPs() {
        return policyInformationPoints;
    }

    /**
     * Gets the size of the buffer, in bytes, used when receiving data.
     * 
     * @return Size of the buffer, in bytes, used when receiving data
     */
    public int getReceiveBufferSize() {
        return receiveBufferSize;
    }

    /**
     * Gets the size of the buffer, in bytes, used when sending data.
     * 
     * @return size of the buffer, in bytes, used when sending data
     */
    public int getSendBufferSize() {
        return sendBufferSize;
    }

    /**
     * Gets the credential used by this service to create SSL connections and digital signatures.
     * 
     * @return credential used by this service to create SSL connections and digital signatures
     */
    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    /**
     * Gets the store containing the trust material used to validate X509 certificates.
     * 
     * @return store containing the trust material used to validate X509 certificates
     */
    public PKIStore getTrustMaterialStore() {
        return trustMaterialStore;
    }

    /**
     * Populates the given configuration with information from this builder.
     * 
     * @param config the configuration to populate
     */
    protected void populateConfiguration(ConfigType config) {
        config.setConnectionTimeout(connectionTimeout);
        config.setMaxRequests(maxConnections);
        config.setPolicyInformationPoints(policyInformationPoints);
        config.setReceiveBufferSize(receiveBufferSize);
        config.setSendBufferSize(sendBufferSize);
        config.setKeyManager(keyManager);
        config.setX509TrustMaterial(trustMaterialStore);
    }

    /**
     * Sets the HTTP connection timeout, in milliseconds.
     * 
     * @param timeout HTTP connection timeout, in milliseconds; may not be less than 1
     */
    public void setConnectionTimeout(int timeout) {
        if (timeout < 1) {
            throw new IllegalArgumentException("Connection timeout may not be less than 1 millisecond");
        }
        connectionTimeout = timeout;
    }

    /**
     * Sets the path to the logging file configuration location.
     * 
     * @param path path to the logging file configuration location
     */
    public void setLoggingConfigFilePath(String path) {
        loggingConfigFilePath = Strings.safeTrimOrNullString(path);
    }

    /**
     * Sets the maximum number of concurrent connections that may be in-process at one time.
     * 
     * @param max maximum number of concurrent connections that may be in-process at one time; may not be less than 1
     */
    public void setMaxConnections(int max) {
        if (max < 1) {
            throw new IllegalArgumentException("Maximum number of threads may not be less than 1");
        }
        maxConnections = max;
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
     * Sets size of the buffer, in bytes, used when receiving data.
     * 
     * @param size size of the buffer, in bytes, used when receiving data; may not be less than 1
     */
    public void setReceiveBufferSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Request buffer size may not be less than 1 byte in size");
        }
        receiveBufferSize = size;
    }

    /**
     * Sets the size of the buffer, in bytes, used when sending data
     * 
     * @param size size of the buffer, in bytes, used when sending data; may not be less than 1
     */
    public void setSendBufferSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("Send buffer size may not be less than 1 byte in size");
        }
        sendBufferSize = size;
    }

    /**
     * Sets the credential used by this service to create SSL connections and digital signatures.
     * 
     * @param manager credential used by this service to create SSL connections and digital signatures
     */
    public void setKeyManager(X509KeyManager manager) {
        keyManager = manager;
    }

    /**
     * Sets the store containing the trust material used to validate X509 certificates.
     * 
     * @param material store containing the trust material used to validate X509 certificates
     */
    protected void setX509TrustMaterial(PKIStore material) {
        trustMaterialStore = material;
    }
}