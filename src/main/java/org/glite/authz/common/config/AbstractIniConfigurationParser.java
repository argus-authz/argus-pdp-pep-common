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

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Files;
import org.glite.authz.common.x509.TrustStoreValidationErrorLogger;
import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;

/**
 * Base class for configuration parsers that employ an INI file.
 * 
 * @param <ConfigurationType>
 *            the type of configuration produced by this parser
 */
@ThreadSafe
public abstract class AbstractIniConfigurationParser<ConfigurationType extends AbstractConfiguration>
        implements ConfigurationParser<ConfigurationType> {

    /**
     * The name of the {@value} INI header which contains the property for
     * configuring credential/trust information.
     */
    public static final String SECURITY_SECTION_HEADER= "SECURITY";

    /**
     * The name of the {@value} which gives the path to the service's private
     * key.
     */
    public static final String SERVICE_KEY_PROP= "servicePrivateKey";

    /**
     * The name of the {@value} which provides the password of the service's
     * private key.
     */
    public static final String SERVICE_KEY_PASSWORD_PROP= "servicePrivateKeyPassword";

    /**
     * The name of the {@value} which gives the path to the service's
     * certificate.
     */
    public static final String SERVICE_CERT_PROP= "serviceCertificate";

    /**
     * The name of the {@value} which gives the path to directory of PEM-encoded
     * trusted X.509 certificates.
     */
    public static final String TRUST_INFO_DIR_PROP= "trustInfoDir";

    /**
     * The name of the {@value} which gives the refresh period, in minutes, for
     * the trust information.
     */
    public static final String TRUST_INFO_REFRSH_PROP= "trustInfoRefresh";

    /**
     * The name of the {@value} which enable or disable CRL revocation and validation for X.509 certificates.
     */
    public static final String ENABLE_CRL_PROP= "enableCRL";

    /**
     * The name of the {@value} which enable or disable OCSP revocation and validation for X.509 certificates.
     */
    public static final String ENABLE_OCSP_PROP= "enableOCSP";
    
    /**
     * The name of the {@value} which gives the maximum number of simultaneous
     * requests.
     */
    public static final String MAX_REQUESTS_PROP= "maximumRequests";

    /** The name of the {@value} which gives the connection timeout, in seconds. */
    public static final String CONN_TIMEOUT_PROP= "connectionTimeout";

    /**
     * The name of the {@value} which gives the size of the receiving message
     * buffer, in bytes.
     */
    public static final String REC_BUFF_SIZE_PROP= "receiveBufferSize";

    /**
     * The name of the {@value} which gives the sending message buffer, in
     * bytes.
     */
    public static final String SEND_BUFF_SIZE_PROP= "sendBufferSize";

    /**
     * Default value of the {@value #TRUST_INFO_REFRSH_PROP} property: {@value}
     * minutes.
     */
    public static final int DEFAULT_TRUST_INFO_REFRESH= 60;

    /** Default value of the {@value #MAX_REQUESTS_PROP} property: {@value} . */
    public static final int DEFAULT_MAX_REQS= 200;

    /**
     * Default value of the {@value #CONN_TIMEOUT_PROP} property: {@value}
     * seconds.
     */
    public static final int DEFAULT_CONN_TIMEOUT= 30;

    /**
     * Default value of the {@value #REC_BUFF_SIZE_PROP} property: {@value}
     * kilobytes.
     */
    public static final int DEFAULT_REC_BUFF_SIZE= 16384;

    /**
     * Default value of the {@value #SEND_BUFF_SIZE_PROP} property: {@value}
     * kilobytes.
     */
    public static final int DEFAULT_SEND_BUFF_SIZE= 16384;

    /**
     * Default value of the {@value #ENABLE_CRL_PROP} property: {@value}
     */
    public static final boolean DEFAULT_ENABLE_CRL= true;

    /**
     * Default value of the {@value #ENABLE_OCSP_PROP} property: {@value}
     */
    public static final boolean DEFAULT_ENABLE_OCSP= false;

    
    /**
     * Default values for the validation and revocation of OpenSSL X.509 certificates
     */
    private final CrlCheckingMode DEFAULT_CRL_CHECKING_MODE= CrlCheckingMode.IF_VALID;
    private final OCSPCheckingMode DEFAULT_OCSP_CHECKING_MODE= OCSPCheckingMode.IGNORE;
    private final NamespaceCheckingMode DEFAULT_NAMESPACE_CHECKING_MODE= NamespaceCheckingMode.EUGRIDPMA_GLOBUS;
    private static final ProxySupport DEFAULT_PROXY_SUPPORT= ProxySupport.ALLOW;

    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(AbstractIniConfigurationParser.class);

    /**
     * Gets the value of the {@value #CONN_TIMEOUT_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_CONN_TIMEOUT} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the timeout in milliseconds
     */
    protected int getConnectionTimeout(Ini.Section configSection) {
        int timeout= IniConfigUtil.getInt(configSection, CONN_TIMEOUT_PROP, DEFAULT_CONN_TIMEOUT, 1, Integer.MAX_VALUE);
        return timeout * 1000;
    }

    /**
     * Gets the value of the {@value #MAX_REQUESTS_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_MAX_REQS} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getMaximumRequests(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, MAX_REQUESTS_PROP, DEFAULT_MAX_REQS, 1, Integer.MAX_VALUE);
    }

    /**
     * Gets the value of the {@value #REC_BUFF_SIZE_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_REC_BUFF_SIZE} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getReceiveBufferSize(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, REC_BUFF_SIZE_PROP, DEFAULT_REC_BUFF_SIZE, 1, Integer.MAX_VALUE);
    }

    /**
     * Gets the value of the {@value #SEND_BUFF_SIZE_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_SEND_BUFF_SIZE} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getSendBufferSize(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, SEND_BUFF_SIZE_PROP, DEFAULT_SEND_BUFF_SIZE, 1, Integer.MAX_VALUE);
    }

    /**
     * Gets the value of the {@value #TRUST_INFO_REFRSH_PROP} property from the
     * configuration section. If the property is not present or is not valid the
     * default value of {@value #DEFAULT_TRUST_INFO_REFRESH} will be used.
     * 
     * @param configSection
     *            configuration section from which to extract the value
     * 
     * @return the refresh interval in minutes
     */
    protected int getTrustMaterialRefreshInterval(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, TRUST_INFO_REFRSH_PROP, DEFAULT_TRUST_INFO_REFRESH, 1, Integer.MAX_VALUE);
    }

    /**
     * Creates a {@link javax.net.ssl.KeyManager} from the
     * {@value #SERVICE_KEY_PROP} and {@value #SERVICE_CERT_PROP} properties, if
     * they exist.
     * 
     * @param configSection
     *            current configuration section being processed
     * 
     * @return the constructed key manager, or null if the required properties
     *         do not exist
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem creating the key manager
     */
    protected X509KeyManager getX509KeyManager(Ini.Section configSection)
            throws ConfigurationException {
        if (configSection == null) {
            return null;
        }
        String name= configSection.getName();
        String privateKeyFilePath= IniConfigUtil.getString(configSection, SERVICE_KEY_PROP, null);
        if (privateKeyFilePath == null) {
            log.info("{}: No service private key file provided, no service credential will be used.", name);
            return null;
        }

        String certificateFilePath= IniConfigUtil.getString(configSection, SERVICE_CERT_PROP, null);
        if (certificateFilePath == null) {
            log.info("{}: No service certificate file provided, no service credential will be used.", name);
            return null;
        }

        // param 'servicePrivateKeyPassword' for encrypted private key
        String privateKeyPassword= IniConfigUtil.getString(configSection, SERVICE_KEY_PASSWORD_PROP, null);

        log.info("{}: service credential certificate: {}", name, certificateFilePath);
        log.info("{}: service credential private key: {}", name, privateKeyFilePath);
        log.info("{}: service credential private key password: {}", name, (privateKeyPassword == null) ? "not set (unencrypted key)" : "set");

        try {
            PEMCredential credential= new PEMCredential(privateKeyFilePath, certificateFilePath, (privateKeyPassword != null) ? privateKeyPassword.toCharArray() : null);
            return credential.getKeyManager();
        } catch (Exception e) {
            log.error("Unable to create service key manager", e);
            throw new ConfigurationException("Unable to read service credential information", e);
        }
    }

    /**
     * Creates a {@link X509TrustManager} from the {@value #TRUST_INFO_DIR_PROP}
     * property, if they exist. This store holds the material used to validate
     * X.509 certificates.
     * 
     * @param configSection
     *            current configuration section being processed
     * 
     * @return the constructed trust material store, or null if the required
     *         attribute did not exist
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem creating the trust manager
     */
    protected X509CertChainValidatorExt getX509CertChainValidator(Ini.Section configSection)
            throws ConfigurationException {
        if (configSection == null) {
            return null;
        }
        String name= configSection.getName();
        String trustStoreDir= IniConfigUtil.getString(configSection, TRUST_INFO_DIR_PROP, null);
        if (trustStoreDir == null) {
            log.info("{}: No truststore directory given, no trust manager will be used", name);
            return null;
        }

        try {
            Files.getFile(trustStoreDir, false, true, true, false);
        } catch (IOException e) {
            log.error("Unable to read truststore directory " + trustStoreDir, e);
            throw new ConfigurationException(e.getMessage());
        }
        log.info("{}: X.509 trust information directory: {}", name, trustStoreDir);

        int refreshInterval= getTrustMaterialRefreshInterval(configSection) * 60 * 1000;
        log.info("{}: X.509 trust information refresh interval: {}ms", name, refreshInterval);

        /* BUG FIX: default MUST be CRL validation and no OCSP validation */
        boolean enableCRL= IniConfigUtil.getBoolean(configSection,
                                                    ENABLE_CRL_PROP, 
                                                    DEFAULT_ENABLE_CRL);
        log.info("{}: X.509 CRL validation: {}", name, enableCRL);
        
        boolean enableOCSP= IniConfigUtil.getBoolean(configSection,
                                                     ENABLE_OCSP_PROP, DEFAULT_ENABLE_OCSP);
        log.info("{}: X.509 OCSP validation: {}", name, enableCRL);

        try {
            CrlCheckingMode crlCheckingMode= DEFAULT_CRL_CHECKING_MODE;
            if (enableCRL) {
                crlCheckingMode= CrlCheckingMode.IF_VALID;
            }
            else {
                crlCheckingMode= CrlCheckingMode.IGNORE;
            }
            OCSPCheckingMode ocspCheckingMode= DEFAULT_OCSP_CHECKING_MODE;
            if (enableOCSP) {
                ocspCheckingMode = OCSPCheckingMode.IF_AVAILABLE;
            }
            else {
                ocspCheckingMode= OCSPCheckingMode.IGNORE;
            }
            NamespaceCheckingMode namespaceCheckingMode= DEFAULT_NAMESPACE_CHECKING_MODE;
            ProxySupport proxySupport= DEFAULT_PROXY_SUPPORT;

            RevocationParametersExt revocationParameters= new RevocationParametersExt(crlCheckingMode, 
                                                                                      new CRLParameters(), 
                                                                                      new OCSPParametes(ocspCheckingMode));
            ValidatorParamsExt validationParams= new ValidatorParamsExt(revocationParameters, proxySupport);
            OpensslCertChainValidator validator= new OpensslCertChainValidator(trustStoreDir, 
                                                                               namespaceCheckingMode, 
                                                                               refreshInterval, 
                                                                               validationParams);

            ValidationErrorListener validationListener= new TrustStoreValidationErrorLogger();
            validator.addValidationListener(validationListener);
            return validator;
        } catch (Exception e) {
            log.error("Unable to create X.509 trust store", e);
            throw new ConfigurationException("Unable to create X.509 trust store", e);
        }
    }
}
