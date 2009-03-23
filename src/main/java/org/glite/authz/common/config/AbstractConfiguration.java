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

import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.obligation.ObligationService;
import org.glite.authz.common.pip.PolicyInformationPoint;

/** Base configuration implementation for PEP clients and daemons. */
@ThreadSafe
public abstract class AbstractConfiguration {

    /** Key under which a configuration object might be bound. */
    public static final String BINDING_NAME = "org.glite.authz.common.config";

    /** A key manager containing the service's credential. */
    private X509KeyManager keyManager;

    /** Trust manager containing the trust certificates and CRLs used by the service. */
    private X509TrustManager trustManager;

    /** Maximum number of concurrent requests that may be in-process at one time. */
    private int maxRequests;

    /** Connection timeout in milliseconds. */
    private int connectionTimeout;

    /** Size of the buffer, in bytes, used when receiving data. */
    private int receiveBufferSize;

    /** Size of the buffer, in bytes, used when sending data. */
    private int sendBufferSize;

    /** Registered policy information points. */
    private List<PolicyInformationPoint> policyInformationPoints;

    /** Service used to handle obligations. */
    private ObligationService obligationService;

    /** Constructor. */
    protected AbstractConfiguration() {
        keyManager = null;
        trustManager = null;
        maxRequests = 0;
        connectionTimeout = 0;
        receiveBufferSize = 0;
        sendBufferSize = 0;
        policyInformationPoints = null;
        obligationService = null;
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
     * Gets the maximum number of concurrent connections that may be in-process at one time.
     * 
     * @return maximum number of concurrent connections that may be in-process at one time
     */
    public int getMaxRequests() {
        return maxRequests;
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
     * Gets the immutable list of registered policy information points.
     * 
     * @return immutable list of registered policy information points
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
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
     * Gets the trust manager used to evaluate X509 certificates.
     * 
     * @return trust manager used to evaluate X509 certificates
     */
    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    /**
     * Sets the HTTP connection timeout, in milliseconds.
     * 
     * @param timeout HTTP connection timeout, in milliseconds; may not be less than 1
     */
    protected synchronized final void setConnectionTimeout(int timeout) {
        if (connectionTimeout != 0) {
            throw new IllegalStateException("The connection timeout has already been set, it may not be changed.");
        }

        if (timeout < 1) {
            throw new IllegalArgumentException("Connection timeout may not be less than 1 millisecond");
        }
        connectionTimeout = timeout;
    }

    /**
     * Sets the maximum number of concurrent connections that may be in-process at one time.
     * 
     * @param max maximum number of concurrent connections that may be in-process at one time; may not be less than 1
     */
    protected synchronized final void setMaxRequests(int max) {
        if (maxRequests != 0) {
            throw new IllegalStateException(
                    "The maximum number of requests has already been set, it may not be changed.");
        }

        if (max < 1) {
            throw new IllegalArgumentException("Maximum number of requests may not be less than 1");
        }
        maxRequests = max;
    }

    /**
     * Sets the service used to handle obligations.
     * 
     * @param service service used to handle obligations
     */
    protected synchronized final void setObligationService(ObligationService service) {
        if (service == null) {
            return;
        }

        if (obligationService != null) {
            throw new IllegalStateException("Obligation service has already been set, it may not be changed");
        }
        obligationService = service;
    }

    /**
     * Sets the list of registered policy information points.
     * 
     * @param pips list of registered policy information points
     */
    protected synchronized final void setPolicyInformationPoints(List<PolicyInformationPoint> pips) {
        if (policyInformationPoints != null) {
            throw new IllegalArgumentException(
                    "A list of registered policy information points has already been set, it may not be changed.");
        }
        if (pips == null) {
            return;
        }

        policyInformationPoints = Collections.unmodifiableList(pips);
    }

    /**
     * Sets size of the buffer, in bytes, used when receiving data.
     * 
     * @param size size of the buffer, in bytes, used when receiving data; may not be less than 1
     */
    protected synchronized final void setReceiveBufferSize(int size) {
        if (receiveBufferSize != 0) {
            throw new IllegalStateException("Receive buffer size has already been set, it may not be changed.");
        }

        if (size < 1) {
            throw new IllegalArgumentException("Receive buffer size may not be less than 1 byte in size");
        }
        receiveBufferSize = size;
    }

    /**
     * Sets the size of the buffer, in bytes, used when sending data
     * 
     * @param size size of the buffer, in bytes, used when sending data; may not be less than 1
     */
    protected synchronized final void setSendBufferSize(int size) {
        if (sendBufferSize != 0) {
            throw new IllegalStateException("Send buffer size has already been set, it may not be changed.");
        }
        if (size < 1) {
            throw new IllegalArgumentException("Response buffer size may not be less than 1 byte in size");
        }
        sendBufferSize = size;
    }

    /**
     * Sets the credential used by this service to create SSL connections and digital signatures.
     * 
     * @param manager credential used by this service to create SSL connections and digital signatures
     */
    protected synchronized final void setKeyManager(X509KeyManager manager) {
        if (keyManager != null) {
            throw new IllegalStateException("The service key manager has already been set, it may not be changed.");
        }
        keyManager = manager;
    }

    /**
     * Sets the trust manager used to evaluate X509 certificates.
     * 
     * @param manager trust manager used to evaluate X509 certificates
     */
    protected synchronized final void setTrustManager(X509TrustManager manager) {
        if (trustManager != null) {
            throw new IllegalStateException("The trust manager has already been set, it may not be changed");
        }
        trustManager = manager;
    }
}