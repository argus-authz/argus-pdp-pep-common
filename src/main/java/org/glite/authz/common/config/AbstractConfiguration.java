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

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.voms.PKIStore;
import org.glite.voms.VOMSTrustManager;

/** Base configuration implementation for PEP clients and daemons. */
@ThreadSafe
public abstract class AbstractConfiguration {

    /** Key under which a configuration object might be bound. */
    public static final String BINDING_NAME = "org.glite.authz.common.config";

    /** A key manager containing the service's credential. */
    private X509KeyManager keyManager;

    /** Store for X.509 store material. */
    private PKIStore trustMaterialStore;

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

    /** Constructor. */
    protected AbstractConfiguration() {
        keyManager = null;
        trustManager = null;
        maxRequests = 0;
        connectionTimeout = 0;
        receiveBufferSize = 0;
        sendBufferSize = 0;
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
     * Gets the store containing the trust material used to validate X509 certificates.
     * 
     * @return store containing the trust material used to validate X509 certificates
     */
    public PKIStore getTrustMaterialStore() {
        return trustMaterialStore;
    }

    /**
     * Sets the HTTP connection timeout, in milliseconds.
     * 
     * @param timeout HTTP connection timeout, in milliseconds; may not be less than 1
     */
    protected final synchronized void setConnectionTimeout(int timeout) {
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
    protected final synchronized void setMaxRequests(int max) {
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
     * Sets size of the buffer, in bytes, used when receiving data.
     * 
     * @param size size of the buffer, in bytes, used when receiving data; may not be less than 1
     */
    protected final synchronized void setReceiveBufferSize(int size) {
        if (receiveBufferSize != 0) {
            throw new IllegalStateException("Receive buffer size has already been set, it may not be changed.");
        }

        if (size < 1) {
            throw new IllegalArgumentException("Receive buffer size may not be less than 1 byte in size");
        }
        receiveBufferSize = size;
    }

    /**
     * Sets the size of the buffer, in bytes, used when sending data.
     * 
     * @param size size of the buffer, in bytes, used when sending data; may not be less than 1
     */
    protected final synchronized void setSendBufferSize(int size) {
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
    protected final synchronized void setKeyManager(X509KeyManager manager) {
        if (keyManager != null) {
            throw new IllegalStateException("The service key manager has already been set, it may not be changed.");
        }
        keyManager = manager;
    }

    /**
     * Sets the store containing the trust material used to validate X509 certificates.
     * 
     * @param material store containing the trust material used to validate X509 certificates
     */
    protected final synchronized void setX509TrustMaterial(PKIStore material) {
        if (trustMaterialStore != null) {
            throw new IllegalStateException(
                    "The X.509 trust material store has already been set, it may not be changed");
        }
        trustMaterialStore = material;
        try {
            trustManager = new VOMSTrustManager(trustMaterialStore);
        } catch (CRLException e) {
            throw new IllegalArgumentException("Error processing CRLs in X.509 trust material", e);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Error processing X509 CA certificates in X.509 trust material", e);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error reading trust information in X.509 trust material", e);
        }
    }
}