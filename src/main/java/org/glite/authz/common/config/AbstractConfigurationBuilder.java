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

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.Strings;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/**
 * Base class for builders of {@link AbstractConfiguration} objects.
 * 
 * @param <ConfigType>
 *          the type of configuration object built
 */
@NotThreadSafe
public abstract class AbstractConfigurationBuilder<ConfigType extends AbstractConfiguration> {

  /** Logging configuration file path. */
  private String loggingConfigFilePath;

  /** A key manager containing the service's credential. */
  private X509KeyManager keyManager;

  /** X.509 cert chain validator */
  private X509CertChainValidatorExt certChainValidator;

  /** X.509 trust material (CA bundle) */
  private X509TrustManager trustManager;

  /**
   * Maximum number of concurrent connections that may be in-process at one
   * time.
   */
  private int maxConnections;

  /** Connection timeout in milliseconds. */
  private int connectionTimeout;

  /** Size of the buffer, in bytes, used when receiving data. */
  private int receiveBufferSize;

  /** Size of the buffer, in bytes, used when sending data. */
  private int sendBufferSize;

  /** Constructor. */
  protected AbstractConfigurationBuilder() {

    maxConnections = 0;
    connectionTimeout = 0;
    receiveBufferSize = 0;
    sendBufferSize = 0;
    keyManager = null;
    trustManager = null;
  }

  /**
   * Constructor thats creates a builder factory with the same settings as the
   * given prototype configuration.
   * 
   * @param prototype
   *          the prototype configuration whose values will be used to
   *          initialize this builder
   */
  protected AbstractConfigurationBuilder(AbstractConfiguration prototype) {

    keyManager = prototype.getKeyManager();
    trustManager = prototype.getTrustManager();
    certChainValidator = prototype.getCertChainValidator();
    maxConnections = prototype.getMaxRequests();
    connectionTimeout = prototype.getConnectionTimeout();
    receiveBufferSize = prototype.getReceiveBufferSize();
    sendBufferSize = prototype.getSendBufferSize();
  }

  /**
   * Builds the configuration represented by the current set properties. Please
   * note that configuration builders are <strong>not</strong> threadsafe. So
   * care should be taken that another thread does not change properties while
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
   * Gets the maximum number of concurrent connections that may be in-process at
   * one time.
   * 
   * @return maximum number of concurrent connections that may be in-process at
   *         one time
   */
  public int getMaxConnections() {

    return maxConnections;
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
   * Gets the credential used by this service to create SSL connections and
   * digital signatures.
   * 
   * @return credential used by this service to create SSL connections and
   *         digital signatures
   */
  public X509KeyManager getKeyManager() {

    return keyManager;
  }

  /**
   * Get the X.509 trust manager
   * 
   * @return the trust manager
   */
  public X509TrustManager getTrustManager() {

    return trustManager;
  }

  /**
   * Returns the X.509 cert chain validator
   * 
   * @return the cert chain validator
   */
  public X509CertChainValidatorExt getCertChainValidator() {

    return certChainValidator;
  }

  /**
   * Set the X.509 cert chain validator
   * 
   * @param validator
   *          the certificate chain validator
   */
  public void setCertChainValidator(X509CertChainValidatorExt validator) {

    certChainValidator = validator;
  }

  /**
   * Populates the given configuration with information from this builder.
   * 
   * @param config
   *          the configuration to populate
   */
  protected void populateConfiguration(ConfigType config) {

    config.setConnectionTimeout(connectionTimeout);
    config.setMaxRequests(maxConnections);
    config.setReceiveBufferSize(receiveBufferSize);
    config.setSendBufferSize(sendBufferSize);
    config.setKeyManager(keyManager);
    config.setCertChainValidator(certChainValidator);
    config.setTrustManager(trustManager);
  }

  /**
   * Sets the HTTP connection timeout, in milliseconds.
   * 
   * @param timeout
   *          HTTP connection timeout, in milliseconds; may not be less than 1
   */
  public void setConnectionTimeout(int timeout) {

    if (timeout < 1) {
      throw new IllegalArgumentException(
        "Connection timeout may not be less than 1 millisecond");
    }
    connectionTimeout = timeout;
  }

  /**
   * Sets the path to the logging file configuration location.
   * 
   * @param path
   *          path to the logging file configuration location
   */
  public void setLoggingConfigFilePath(String path) {

    loggingConfigFilePath = Strings.safeTrimOrNullString(path);
  }

  /**
   * Sets the maximum number of concurrent connections that may be in-process at
   * one time.
   * 
   * @param max
   *          maximum number of concurrent connections that may be in-process at
   *          one time; may not be less than 1
   */
  public void setMaxConnections(int max) {

    if (max < 1) {
      throw new IllegalArgumentException(
        "Maximum number of threads may not be less than 1");
    }
    maxConnections = max;
  }

  /**
   * Sets size of the buffer, in bytes, used when receiving data.
   * 
   * @param size
   *          size of the buffer, in bytes, used when receiving data; may not be
   *          less than 1
   */
  public void setReceiveBufferSize(int size) {

    if (size < 1) {
      throw new IllegalArgumentException(
        "Request buffer size may not be less than 1 byte in size");
    }
    receiveBufferSize = size;
  }

  /**
   * Sets the size of the buffer, in bytes, used when sending data.
   * 
   * @param size
   *          size of the buffer, in bytes, used when sending data; may not be
   *          less than 1
   */
  public void setSendBufferSize(int size) {

    if (size < 1) {
      throw new IllegalArgumentException(
        "Send buffer size may not be less than 1 byte in size");
    }
    sendBufferSize = size;
  }

  /**
   * Sets the credential used by this service to create SSL connections and
   * digital signatures.
   * 
   * @param manager
   *          credential used by this service to create SSL connections and
   *          digital signatures
   */
  public void setKeyManager(X509KeyManager manager) {

    keyManager = manager;
  }

  /**
   * Sets the trust manager used to validate X509 certificates.
   * 
   * @param manager
   *          the trust manager
   * 
   * 
   */
  public void setTrustManager(X509TrustManager manager) {

    trustManager = manager;
  }
}