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

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for configuration parsers that employ an INI file.
 * 
 * @param <ConfigurationType> the type of configuration produced by this parser
 */
public abstract class AbstractIniServiceConfigurationParser<ConfigurationType extends AbstractServiceConfiguration>
        extends AbstractIniConfigurationParser<ConfigurationType> {

    /** The name of the {@value} INI header which contains the property for configuring the service. */
    public static final String SERVICE_SECTION_HEADER = "SERVICE";

    /** The name of the {@value} property which indicates the unique identity of the service. */
    public static final String ENTITY_ID_PROP = "entityId";

    /** The name of the {@value} property which indicates the service hostname. */
    public static final String HOST_PROP = "hostname";

    /** The name of the {@value} property which indicates the port to which the service will bind. */
    public static final String PORT_PROP = "port";
    
    /** The name of the {@value} property which indicates that the service port should use SSL instead of plain HTTP. */
    public static final String SSL_ON_PORT_PROP="enableSSL";

    /** The name of the {@value} property which indicates the port the service will listen on for shutdown commands. */
    public static final String SD_PORT_PROP = "shutdownPort";

    /** The name of the {@value} property which indicates the maximum number of requests that will be queued up. */
    public static final String REQUEST_QUEUE_PROP = "requestQueueSize";

    /** Default value of the {@value #SSL_ON_PORT_PROP} property, {@value} . */
    public static final boolean DEFAULT_SSL_ON_PORT = false;
    
    /** Default value of the {@value #REQUEST_QUEUE_PROP} property, {@value} . */
    public static final int DEFAULT_REQUEST_QUEUE = 50;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractIniServiceConfigurationParser.class);

    /**
     * Gets the value of the {@value #ENTITY_ID_PROP} property from the configuration section.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value
     * 
     * @throws ConfigurationException thrown if the entity ID property is not set or has an empty value
     */
    protected String getEntityId(Section configSection) throws ConfigurationException {
        return IniConfigUtil.getString(configSection, ENTITY_ID_PROP);
    }

    /**
     * Gets the value of the {@value #HOST_PROP} property from the configuration section. If the property is not present
     * or is not valid the default value of {@value #DEFAULT_HOST} will be used.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value
     * 
     * @throws ConfigurationException thrown if no host name is given
     */
    protected String getHostname(Section configSection) throws ConfigurationException {
        return IniConfigUtil.getString(configSection, HOST_PROP);
    }

    /**
     * Gets the value of the {@value #PORT_PROP} property from the configuration section.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value, or 0 if it is not set
     */
    protected int getPort(Section configSection){
        return IniConfigUtil.getInt(configSection, PORT_PROP, 0, 1, 65535);
    }
    
    /**
     * Gets the value of the {@value #SSL_ON_PORT_PROP} property from the configuration section.
     *
     * @param configSection configuration section from which to extract the value
     * 
     * @return whether SSL should be enabled on the service port, defaults to {@value #DEFAULT_SSL_ON_PORT}.
     */
    protected boolean isSSLEnabled(Section configSection){
        return IniConfigUtil.getBoolean(configSection, SSL_ON_PORT_PROP, DEFAULT_SSL_ON_PORT);
    }

    /**
     * Gets the value of the {@value #SD_PORT_PROP} property from the configuration section.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value, or 0 if is not set
     */
    protected int getShutdownPort(Section configSection) {
        return IniConfigUtil.getInt(configSection, SD_PORT_PROP, 0, 1, 65535);
    }

    /**
     * Gets the value of the {@value #REQUEST_QUEUE_PROP} property from the configuration section. If the property is
     * not present or is not valid the default value of {@value #DEFAULT_REQUEST_QUEUE} will be used.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getMaxRequestQueueSize(Section configSection) {
        return IniConfigUtil.getInt(configSection, REQUEST_QUEUE_PROP, DEFAULT_REQUEST_QUEUE, 1, Integer.MAX_VALUE);
    }

    /**
     * Process the information contained in the {@value #SERVICE_SECTION_HEADER} configuration section.
     * 
     * @param iniFile INI file being processed
     * @param configBuilder builder being populated with configuration information
     * 
     * @throws ConfigurationException thrown if there is a problem reading the information contained in the
     *             {@value #SERVICE_SECTION_HEADER} section
     */
    protected void processServiceSection(Ini iniFile, AbstractServiceConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        Section configSection = iniFile.get(SERVICE_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "INI configuration does not contain the required '" + SERVICE_SECTION_HEADER
                    + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        String entityId = getEntityId(configSection);
        log.info("entity ID: {}", entityId);
        configBuilder.setEntityId(entityId);

        String host = getHostname(configSection);
        log.info("service host address: {}", host);
        configBuilder.setHost(host);

        int port = getPort(configSection);
        log.info("service listening port: {}", port);
        configBuilder.setPort(port);
        
        boolean sslOn = isSSLEnabled(configSection);
        log.info("service port using SSL: {}", sslOn);
        configBuilder.setSslEnabled(sslOn);

        int shutdownPort = getShutdownPort(configSection);
        log.info("service shutdown port: {}", (shutdownPort == 0 ? "default" : shutdownPort));
        configBuilder.setShutdownPort(shutdownPort);

        int maxConnections = getMaximumRequests(configSection);
        log.info("max requests: {}", maxConnections);
        configBuilder.setMaxConnections(maxConnections);

        int connTimeout = getConnectionTimeout(configSection);
        log.info("connection timeout: {}ms", connTimeout);
        configBuilder.setConnectionTimeout(connTimeout);

        int maxReqQueue = getMaxRequestQueueSize(configSection);
        log.info("max request queue size: {}", maxReqQueue);
        configBuilder.setMaxRequestQueueSize(maxReqQueue);

        int receiveBuffer = getReceiveBufferSize(configSection);
        log.info("recieve buffer size: {} bytes", receiveBuffer);
        configBuilder.setReceiveBufferSize(receiveBuffer);

        int sendBuffer = getSendBufferSize(configSection);
        log.info("send buffer size: {} bytes", sendBuffer);
        configBuilder.setSendBufferSize(sendBuffer);

        configBuilder.setKeyManager(getX509KeyManager(iniFile.get(SECURITY_SECTION_HEADER)));
        configBuilder.setX509TrustMaterial(getX509TrustMaterialStore(iniFile.get(SECURITY_SECTION_HEADER)));

        processObligationHandlers(iniFile, configSection, configBuilder);

        processPolicyInformationPoints(iniFile, configSection, configBuilder);
    }

    /**
     * Builds a SOAP client builder from the information contained in the configuration section.
     * 
     * @param configSection client configuration
     * @param keyManager key manager used for outbound SSL/TLS connections
     * @param trustManager trust manager used for inbound SSL/TLS connections
     * 
     * @return the constructed SOAP client
     */
    protected HttpClientBuilder buildSOAPClientBuilder(Section configSection, X509KeyManager keyManager,
            X509TrustManager trustManager) {
        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");

        int conTimeout = getConnectionTimeout(configSection);
        log.info("connection timeout: {}ms", conTimeout);
        httpClientBuilder.setConnectionTimeout(conTimeout);

        int maxRequests = getMaximumRequests(configSection);
        log.info("maximum requests: {}", maxRequests);
        httpClientBuilder.setMaxTotalConnections(maxRequests);
        httpClientBuilder.setMaxConnectionsPerHost(maxRequests);

        int recBuffSize = getSendBufferSize(configSection);
        log.info("recieve buffer size: {} bytes", recBuffSize);
        httpClientBuilder.setReceiveBufferSize(recBuffSize);

        int sendBuffSize = getSendBufferSize(configSection);
        log.info("send buffer size: {} bytes", sendBuffSize);
        httpClientBuilder.setSendBufferSize(sendBuffSize);

        if (keyManager != null && trustManager != null) {
            log.debug("adding configured X509 key & trust manager to SOAP client");
            TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        return httpClientBuilder;
    }
}