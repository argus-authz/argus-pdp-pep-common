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

import java.io.IOException;
import java.util.List;
import java.util.StringTokenizer;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.pip.IniPIPConfigurationParser;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;
import org.glite.security.trustmanager.ContextWrapper;
import org.glite.security.trustmanager.OpensslTrustmanager;
import org.glite.security.trustmanager.UpdatingKeyManager;
import org.glite.security.util.CaseInsensitiveProperties;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for configuration parsers that employ an INI file.
 * 
 * @param <ConfigurationType> the type of configuration produced by this parser
 */
@ThreadSafe
public abstract class AbstractIniConfigurationParser<ConfigurationType extends AbstractConfiguration> implements
        ConfigurationParser<ConfigurationType> {

    /** Property name for the property giving the file system path to the logging configuration. */
    public static final String LOG_CONFIG_PATH_PROP = "logConfiguration";
    
    /** Property name for the property giving the file system path to the services private key. */
    public static final String SERVICE_KEY_PROP = "privateKey";

    /** Property name for the property giving the file system path to the services X.509 certificate. */
    public static final String SERVICE_CERT_PROP = "certificate";

    /** Name of the property giving the directory in which PEM encoded trusted X.509 certificates are stored. */
    public static final String TRUST_ANCHOR_DIR_PROP = "trustedCertificates";

    /** Name of the property indicating that CRLs must be present during trust evaluation. */
    public static final String CRLS_REQUIRED_PROP = "requireCRLs";

    /** Property name for the maximum number of simultaneous connections configuration property. */
    public static final String MAX_REQUESTS_PROP = "maximumRequests";

    /** Property name for the connection read timeout configuration property. */
    public static final String CONN_TIMEOUT_PROP = "connectionTimeout";

    /** Property name for the receiving buffer size configuration property. */
    public static final String REC_BUFF_SIZE_PROP = "receiveBufferSize";

    /** Property name for the sending buffer size configuration property. */
    public static final String SEND_BUFF_SIZE_PROP = "sendBufferSize";

    /** Property name containing the space-delimited lists of to-be-configured PIPs. */
    public static final String PIP_PROP = "pips";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractIniConfigurationParser.class);

    /**
     * Process a configuration section, looking for the {@value #PIP_PROP} configuration property and, if present,
     * parsing the identified PIP configuration sections
     * 
     * @param configSection configuration section containing the @value #PIP_PROP} configuration property
     * @param iniFile INI file containing the PIP configuration sections
     * 
     * @return configured PIPs, never null;
     * 
     * @throws ConfigurationException thrown if there is a problem configuring the PIPs
     */
    protected List<PolicyInformationPoint> processPolicyInformationPoints(Section configSection, Ini iniFile)
            throws ConfigurationException {
        LazyList<PolicyInformationPoint> pips = new LazyList<PolicyInformationPoint>();

        String pipsStr = Strings.safeTrimOrNullString(configSection.get(PIP_PROP));
        if (pipsStr == null) {
            return pips;
        }

        log.debug("PDP registered PIPs: {}", pipsStr);
        StringTokenizer pipNames = new StringTokenizer(pipsStr, " ");
        while (pipNames.hasMoreTokens()) {
            String pipName = pipNames.nextToken();

            Section pipConfigSection = iniFile.get(pipName);
            if (pipConfigSection == null) {
                String errorMsg = "Unable to find configuration section for PIP " + pipName;
                log.error(errorMsg);
                throw new ConfigurationException(errorMsg);
            }

            pips.add(processPolicyInformationPoint(pipConfigSection));
        }
        return pips;
    }

    /**
     * Processes each individual PIP configuration section.
     * 
     * @param pipConfig the PIP configuration section
     * 
     * @return the PIP configured with the information provided in the configuration section
     * 
     * @throws ConfigurationException throw if a PIP can not be instantiated
     */
    @SuppressWarnings("unchecked")
    protected PolicyInformationPoint processPolicyInformationPoint(Section pipConfig) throws ConfigurationException {
        String parserClassName = Strings.safeTrimOrNullString(pipConfig
                .get(IniPIPConfigurationParser.PARSER_CLASS_PROP));
        if (parserClassName == null) {
            String errorMsg = "PIP configuration section " + pipConfig.getName() + " does not contain a valid "
                    + IniPIPConfigurationParser.PARSER_CLASS_PROP + " configuration property.";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        try {
            log.debug("Creating INI PIP parser class {}", parserClassName);
            Class<IniPIPConfigurationParser> parserClass = (Class<IniPIPConfigurationParser>) AbstractIniConfigurationParser.class
                    .getClassLoader().loadClass(parserClassName);
            IniPIPConfigurationParser parser = parserClass.getConstructor().newInstance();
            return parser.parse(pipConfig);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to configure PIP " + pipConfig.getName(), e);
        }
    }

    /**
     * Creates a trust manager from the X509 trust information provided in the configuration section.
     * 
     * @param configSection the configuration section
     * 
     * @return the X509 trust manager
     * 
     * @throws ConfigurationException throw if the trust information can not be read and used
     */
    protected X509TrustManager processX509TrustInformation(Section configSection) throws ConfigurationException {
        String trustStoreDir = Strings.safeTrimOrNullString(configSection.get(TRUST_ANCHOR_DIR_PROP));

        if (trustStoreDir == null) {
            log.debug("No truststore directory given, no trust manager will be used");
            return null;
        }

        try {
            Files.getFile(trustStoreDir, false, true, true, false);
        } catch (IOException e) {
            log.error("Unable to read truststore directory " + trustStoreDir, e);
            throw new ConfigurationException(e.getMessage());
        }
        log.debug("Using the directory {} as the truststore directory", trustStoreDir);

        boolean crlsRequired = true;
        if (configSection.containsKey(CRLS_REQUIRED_PROP)) {
            crlsRequired = Boolean.parseBoolean(configSection.get(CRLS_REQUIRED_PROP));
        }
        log.debug("CRLs required in the truststore: {}", crlsRequired);

        try {
            return new OpensslTrustmanager(trustStoreDir, crlsRequired);
        } catch (Exception e) {
            log.error("Unable to create trust manager", e);
            throw new ConfigurationException("Unable to read trust information", e);
        }
    }

    /**
     * Creates a key manager, containing the service's credential, from the information in the configuration section.
     * 
     * @param configSection the configuration section
     * 
     * @return the key manager containing the services credential
     * 
     * @throws ConfigurationException thrown if the credential information can not be read
     */
    protected X509KeyManager processX509KeyInformation(Section configSection) throws ConfigurationException {
        String privateKeyFilePath = Strings.safeTrim(configSection.get(SERVICE_KEY_PROP));
        if (privateKeyFilePath == null) {
            log.info("No service private key file provided, no service credential will be used.");
            return null;
        }

        String certificateFilePath = Strings.safeTrim(configSection.get(SERVICE_CERT_PROP));
        if (certificateFilePath == null) {
            log.info("No service certificate file provided, no service credential will be used.");
            return null;
        }

        log.info("Service credential will use private key {} and certificate {}", privateKeyFilePath,
                certificateFilePath);
        CaseInsensitiveProperties keystoreProps = new CaseInsensitiveProperties();
        keystoreProps.setProperty(ContextWrapper.CREDENTIALS_KEY_FILE, privateKeyFilePath);
        keystoreProps.setProperty(ContextWrapper.CREDENTIALS_CERT_FILE, certificateFilePath);

        try {
            return new UpdatingKeyManager(keystoreProps, null);
        } catch (Exception e) {
            log.error("Unable to create service key manager", e);
            throw new ConfigurationException("Unable to read service credential information", e);
        }
    }
}