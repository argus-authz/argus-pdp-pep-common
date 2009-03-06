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
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;

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
    private X509KeyManager serviceCredential;

    /** Trust manager containing the trust certificates and CRLs used by the service. */
    private X509TrustManager trustManager;

    /** Maximum number of concurrent connections that may be in-process at one time. */
    private int maxConnections;

    /** Connection timeout in milliseconds. */
    private int connectionTimeout;

    /** Size of the buffer, in bytes, used when receiving data. */
    private int receiveBufferSize;

    /** Size of the buffer, in bytes, used when sending data. */
    private int sendBufferSize;

    /** Registered policy information points. */
    private List<PolicyInformationPoint> pips;

    /** Constructor. */
    protected AbstractConfigurationBuilder() {
        maxConnections = 100;

        // 30 seconds
        connectionTimeout = 1000 * 30;

        // 4KB
        receiveBufferSize = 1024 * 4;
        sendBufferSize = 1024 * 4;

        pips = new ArrayList<PolicyInformationPoint>();
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
     * Sets the path to the logging file configuration location.
     * 
     * @param path path to the logging file configuration location
     */
    public void setLoggingConfigFilePath(String path) {
        loggingConfigFilePath = Strings.safeTrimOrNullString(path);
    }
    
    /**
     * Constructor thats creates a builder factory with the same settings as the given prototype configuration.
     * 
     * @param prototype the prototype configuration whose values will be used to initialize this builder
     */
    protected AbstractConfigurationBuilder(AbstractConfiguration prototype){
        maxConnections = prototype.getMaxRequests();
        connectionTimeout = prototype.getConnectionTimeout();
        receiveBufferSize = prototype.getReceiveBufferSize();
        sendBufferSize = prototype.getSendBufferSize();
        
        if(prototype.getPolicyInformationPoints() != null){
            pips = new ArrayList<PolicyInformationPoint>(prototype.getPolicyInformationPoints());
        }else{
            pips = new ArrayList<PolicyInformationPoint>();
        }
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
     * Gets the connection socket timeout, in milliseconds.
     * 
     * @return connection socket timeout, in milliseconds
     */
    public int getConnectionTimeout() {
        return connectionTimeout;
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
     * Gets the size of the buffer, in bytes, used when receiving data.
     * 
     * @return Size of the buffer, in bytes, used when receiving data
     */
    public int getReceiveBufferSize() {
        return receiveBufferSize;
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
     * Gets the size of the buffer, in bytes, used when sending data.
     * 
     * @return size of the buffer, in bytes, used when sending data
     */
    public int getSendBufferSize() {
        return sendBufferSize;
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
     * Gets the list of registered PIPs.
     * 
     * @return list of registered PIPs
     */
    public List<PolicyInformationPoint> getPIPs() {
        return pips;
    }

    /**
     * Gets the credential used by this service to create SSL connections and digital signatures.
     * 
     * @return credential used by this service to create SSL connections and digital signatures
     */
    public X509KeyManager getServiceCredential() {
        return serviceCredential;
    }

    /**
     * Sets the credential used by this service to create SSL connections and digital signatures.
     * 
     * @param manager credential used by this service to create SSL connections and digital signatures
     */
    public void setServiceCredential(X509KeyManager manager) {
        serviceCredential = manager;
    }

    /**
     * Gets the trust manager used to evaluate X509 certificates.
     * 
     * @return trust manager used to evaluate X509 certificates
     */
    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    /**
     * Sets the trust manager used to evaluate X509 certificates.
     * 
     * @param manager trust manager used to evaluate X509 certificates
     */
    public void setTrustManager(X509TrustManager manager) {
        trustManager = manager;
    }

    /**
     * Populates the given configuration with information from this builder.
     * 
     * @param config the configuration to populate
     */
    protected void populateConfiguration(AbstractConfiguration config) {
        config.setConnectionTimeout(connectionTimeout);
        config.setMaxRequests(maxConnections);
        config.setPolicyInformationPoints(pips);
        config.setReceiveBufferSize(receiveBufferSize);
        config.setSendBufferSize(sendBufferSize);
        config.setServiceCredential(serviceCredential);
        config.setTrustManager(trustManager);
    }
}