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

import java.io.Reader;
import java.io.StringReader;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.ini4j.Ini;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.CommonX509TrustManager;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/**
 * Base class for configuration parsers that employ an INI file.
 * 
 * @param <ConfigurationType>
 *            the type of configuration produced by this parser
 */
public abstract class AbstractIniServiceConfigurationParser<ConfigurationType extends AbstractServiceConfiguration>
        extends AbstractIniConfigurationParser<ConfigurationType> {

    /**
     * The name of the {@value} INI header which contains the property for
     * configuring the service.
     */
    public static final String SERVICE_SECTION_HEADER= "SERVICE";

    /**
     * The name of the {@value} property which indicates the unique identity of
     * the service.
     */
    public static final String ENTITY_ID_PROP= "entityId";

    /** The name of the {@value} property which indicates the service hostname. */
    public static final String HOST_PROP= "hostname";

    /**
     * The name of the {@value} property which indicates the port to which the
     * service will bind.
     */
    public static final String PORT_PROP= "port";

    /**
     * The name of the {@value} property which indicates that the service port
     * should use SSL instead of plain HTTP.
     */
    public static final String SSL_ON_PORT_PROP= "enableSSL";

    /**
     * The name of the {@value} property which indicates that client certificate
     * authentication is required.
     */
    public static final String CLIENT_CERT_AUTHN_PROP= "requireClientCertAuthentication";

    /**
     * The name of the {@value} property which indicates the host the service
     * will listen on for admin commands.
     */
    public static final String ADMIN_HOST_PROP= "adminHost";

    /** Default value of the {@value #ADMIN_HOST_PROP} property: {@value} . */
    public static final String DEFAULT_ADMIN_HOST= "localhost";

    /**
     * The name of the {@value} property which indicates the port the service
     * will listen on for admin commands.
     */
    public static final String ADMIN_PORT_PROP= "adminPort";

    /**
     * The name of the {@value} property which indicates the password required
     * for admin commands.
     */
    public static final String ADMIN_PASSWORD_PROP= "adminPassword";

    /**
     * The name of the {@value} property which indicates the maximum number of
     * requests that will be queued up.
     */
    public static final String REQUEST_QUEUE_PROP= "requestQueueSize";

    /** Default value of the {@value #SSL_ON_PORT_PROP} property, {@value} . */
    public static final boolean DEFAULT_SSL_ON_PROP= false;

    /**
     * Default value of the {@value #CLIENT_CERT_AUTHN_PROP} property, {@value}
     * .
     */
    public static final boolean DEFAULT_CLIENT_CERT_AUTH= false;

    /** Default value of the {@value #REQUEST_QUEUE_PROP} property, {@value} . */
    public static final int DEFAULT_REQUEST_QUEUE= 500;

    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(AbstractIniServiceConfigurationParser.class);

    /** {@inheritDoc} */
    public ConfigurationType parse(Reader iniReader)
            throws ConfigurationException {
        return parseIni(iniReader);
    }

    /** {@inheritDoc} */
    public ConfigurationType parse(String iniString)
            throws ConfigurationException {
        return parseIni(new StringReader(iniString));
    }

    /**
     * Parse the ini configuration file.
     * 
     * @param iniReader
     *            the ini file reader
     * @return the parsed configuration object
     * @throws ConfigurationException
     *             if a parsing error occurs while parsing the ini file.
     */
    abstract protected ConfigurationType parseIni(Reader iniReader)
            throws ConfigurationException;

    /**
     * Gets the value of the {@value #ENTITY_ID_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     * 
     * @throws ConfigurationException
     *             thrown if the entity ID property is not set or has an empty
     *             value
     */
    protected String getEntityId(Ini.Section configSection)
            throws ConfigurationException {
        return IniConfigUtil.getString(configSection, ENTITY_ID_PROP);
    }

    /**
     * Gets the value of the {@value #HOST_PROP} property from the configuration
     * section. If the property is not present or is not valid the default value
     * of {@value #DEFAULT_HOST} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     * 
     * @throws ConfigurationException
     *             thrown if no host name is given
     */
    protected String getHostname(Ini.Section configSection)
            throws ConfigurationException {
        return IniConfigUtil.getString(configSection, HOST_PROP);
    }

    /**
     * Gets the value of the {@value #PORT_PROP} property from the configuration
     * section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value, or 0 if it is not set
     */
    protected int getPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, PORT_PROP, 0, 1, 65535);
    }

    /**
     * Gets the value of the {@value #SSL_ON_PORT_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return whether SSL should be enabled on the service port, defaults to
     *         {@value #DEFAULT_SSL_ON_PROP}.
     */
    protected boolean isSSLEnabled(Ini.Section configSection) {
        if (configSection == null)
            return DEFAULT_SSL_ON_PROP;
        if (configSection.containsKey(SERVICE_KEY_PROP)
                && configSection.containsKey(SERVICE_CERT_PROP)
                && configSection.containsKey(TRUST_INFO_DIR_PROP)) {
            return IniConfigUtil.getBoolean(configSection, SSL_ON_PORT_PROP, DEFAULT_SSL_ON_PROP);
        }
        else {
            return DEFAULT_SSL_ON_PROP;
        }
    }

    /**
     * Gets the value of the {@value #CLIENT_CERT_AUTHN_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return whether client certificate authentication is required when a
     *         client is connecting, defaults to
     *         {@value #DEFAULT_CLIENT_CERT_AUTH}.
     */
    protected boolean isClientCertAuthRequired(Ini.Section configSection) {
        if (configSection == null)
            return DEFAULT_CLIENT_CERT_AUTH;
        if (isSSLEnabled(configSection)) {
            return IniConfigUtil.getBoolean(configSection, CLIENT_CERT_AUTHN_PROP, DEFAULT_CLIENT_CERT_AUTH);
        }
        else {
            return DEFAULT_CLIENT_CERT_AUTH;
        }
    }

    /**
     * Gets the value of the {@value #ADMIN_HOST_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the admin host value, or the default admin host
     *         {@value #DEFAULT_ADMIN_HOST} if it is not set
     */
    protected String getAdminHost(Ini.Section configSection) {
        return IniConfigUtil.getString(configSection, ADMIN_HOST_PROP, DEFAULT_ADMIN_HOST);
    }

    /**
     * Gets the value of the {@value #ADMIN_PORT_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value, or 0 if is not set
     */
    protected int getAdminPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, ADMIN_PORT_PROP, 0, 1, 65535);
    }

    /**
     * Gets the value of the {@value #ADMIN_PASSWORD_PROP} property from the
     * configuration section.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value or null if it is not set
     */
    protected String getAdminPassword(Ini.Section configSection) {
        return IniConfigUtil.getString(configSection, ADMIN_PASSWORD_PROP, null);
    }

    /**
     * Gets the value of the {@value #REQUEST_QUEUE_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_REQUEST_QUEUE} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getMaxRequestQueueSize(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, REQUEST_QUEUE_PROP, DEFAULT_REQUEST_QUEUE, 1, Integer.MAX_VALUE);
    }

    /**
     * Process the information contained in the {@value #SERVICE_SECTION_HEADER}
     * configuration section.
     * 
     * @param iniFile
     *            INI file being processed
     * @param configBuilder
     *            builder being populated with configuration information
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem reading the information
     *             contained in the {@value #SERVICE_SECTION_HEADER} section
     */
    protected void processServiceSection(Ini iniFile,
                                         AbstractServiceConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        Ini.Section configSection= iniFile.get(SERVICE_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg= "INI configuration does not contain the required '"
                    + SERVICE_SECTION_HEADER + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }
        String name= configSection.getName();

        String entityId= getEntityId(configSection);
        log.info("{}: entity ID: {}", name, entityId);
        configBuilder.setEntityId(entityId);

        String host= getHostname(configSection);
        log.info("{}: service hostname: {}", name, host);
        configBuilder.setHost(host);

        int port= getPort(configSection);
        log.info("{}: service port: {}", name, port);
        configBuilder.setPort(port);

        String adminHost= getAdminHost(configSection);
        log.info("{}: service admin hostname: {}", name, adminHost == null ? "default" : adminHost);
        configBuilder.setAdminHost(adminHost);

        int adminPort= getAdminPort(configSection);
        log.info("{}: service admin port: {}", name, adminPort == 0 ? "default" : adminPort);
        configBuilder.setAdminPort(adminPort);

        String adminPassword= getAdminPassword(configSection);
        log.info("{}: service admin password set: {}", name, adminPassword == null ? "no" : "yes");
        configBuilder.setAdminPassword(adminPassword);

        int maxConnections= getMaximumRequests(configSection);
        log.info("{}: max requests: {}", name, maxConnections);
        configBuilder.setMaxConnections(maxConnections);

        int connTimeout= getConnectionTimeout(configSection);
        log.info("{}: connection timeout: {}ms", name, connTimeout);
        configBuilder.setConnectionTimeout(connTimeout);

        int maxReqQueue= getMaxRequestQueueSize(configSection);
        log.info("{}: max request queue size: {}", name, maxReqQueue);
        configBuilder.setMaxRequestQueueSize(maxReqQueue);

        int receiveBuffer= getReceiveBufferSize(configSection);
        log.info("{}: recieve buffer size: {} bytes", name, receiveBuffer);
        configBuilder.setReceiveBufferSize(receiveBuffer);

        int sendBuffer= getSendBufferSize(configSection);
        log.info("{}: send buffer size: {} bytes", name, sendBuffer);
        configBuilder.setSendBufferSize(sendBuffer);

    }

    /**
     * Process the information contained in the
     * {@value #SECURITY_SECTION_HEADER} configuration section.
     * 
     * @param iniFile
     *            INI file being processed
     * @param configBuilder
     *            builder being populated with configuration information
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem reading the information
     *             contained in the {@value #SECURITY_SECTION_HEADER} section
     */
    protected void processSecuritySection(Ini iniFile,
                                          AbstractServiceConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        Ini.Section securityConfig= iniFile.get(SECURITY_SECTION_HEADER);
        if (securityConfig == null) {
            log.warn("INI configuration does not contain the '{}' section", SECURITY_SECTION_HEADER);
        }

        String name= securityConfig.getName();
        
        // service crenditial
        X509KeyManager x509KeyManager= getX509KeyManager(securityConfig);
        configBuilder.setKeyManager(x509KeyManager);

        // trust information
        X509CertChainValidatorExt validator= getX509CertChainValidator(securityConfig);        
        X509TrustManager x509TrustManager= new CommonX509TrustManager(validator);
        configBuilder.setTrustManager(x509TrustManager);

        boolean sslOn= isSSLEnabled(securityConfig);
        log.info("{}: service port using SSL: {}", name, sslOn);
        configBuilder.setSslEnabled(sslOn);

        boolean clientCertAuthRequired= isClientCertAuthRequired(securityConfig);
        log.info("{}: TLS client certificate authentication required: {}", name, clientCertAuthRequired);
        configBuilder.setClientCertAuthRequired(clientCertAuthRequired);
    }

    /**
     * Builds a SOAP client builder from the information contained in the
     * configuration section.
     * 
     * @param configSection
     *            client configuration
     * @param keyManager
     *            key manager used for outbound SSL/TLS connections
     * @param trustManager
     *            trust manager used for inbound SSL/TLS connections
     * 
     * @return the constructed SOAP client
     */
    protected HttpClientBuilder buildSOAPClientBuilder(Ini.Section configSection,
                                                       X509KeyManager keyManager,
                                                       X509TrustManager trustManager) {
        String name= configSection.getName();
        log.info("{}: building SOAP client ({})", name, (keyManager != null && trustManager != null) ? "SSL" : "plain");
        HttpClientBuilder httpClientBuilder= new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");
        int conTimeout= getConnectionTimeout(configSection);
        log.info("{}: connection timeout: {}ms", name, conTimeout);
        httpClientBuilder.setConnectionTimeout(conTimeout);

        int maxRequests= getMaximumRequests(configSection);
        log.info("{}: maximum requests: {}", name, maxRequests);
        httpClientBuilder.setMaxTotalConnections(maxRequests);
        httpClientBuilder.setMaxConnectionsPerHost(maxRequests);

        int recBuffSize= getSendBufferSize(configSection);
        log.info("{}: recieve buffer size: {} bytes", name, recBuffSize);
        httpClientBuilder.setReceiveBufferSize(recBuffSize);

        int sendBuffSize= getSendBufferSize(configSection);
        log.info("{}: send buffer size: {} bytes", name, sendBuffSize);
        httpClientBuilder.setSendBufferSize(sendBuffSize);

        if (keyManager != null && trustManager != null) {
            log.debug("adding configured X509 key & trust manager to SOAP client");
            TLSProtocolSocketFactory factory= new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        return httpClientBuilder;
    }

}
