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

package org.glite.authz.common.pip.provider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.glite.security.util.CertUtil;
import org.glite.security.util.FileCertReader;
import org.glite.voms.FQAN;
import org.glite.voms.PKIStore;
import org.glite.voms.VOMSAttribute;
import org.glite.voms.VOMSValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A policy information point that extracts information from a X.509, version 3, certificate. The certificate may
 * include VOMS attribute certificates. All extract information is added to the subject(s) containing a valid
 * certificate chain.
 * 
 * The PEM encoded end entity certificate, and its certificate chain, are expected to be bound to the subject attribute
 * {@value #X509_CERT_CHAIN_ID}. Only one end-entity certificate may be present in the chain. If the end entity
 * certificate contains a VOMS attribute certificate, and VOMS certificate validation is enabled, information from that
 * attribute certificate will also be added to the subject. Only one VOMS attribute certificate may be present in the
 * end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS website</a>
 */
public class X509PolicyInformationPoint implements PolicyInformationPoint {

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate processed by the PIP. */
    public final static String X509_CERT_CHAIN_ID = "http://authz-interop.org/xacml/subject/cert-chain";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's issuer's DN. */
    public final static String X509_DN_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's serial number. */
    public final static String X509_SN = "http://authz-interop.org/xacml/subject/certificate-serial-number";

    /** The ID of the subject attribute, {@value} , containing the VO given in the VOMS attribute certificate. */
    public final static String VOMS_VO = "http://authz-interop.org/xacml/subject/vo";

    /**
     * The ID of the subject attribute, {@value} , containing the DN of the VOMS service that signed the VOMS attribute
     * certificate.
     */
    public final static String VOMS_SIGNER = "http://authz-interop.org/xacml/subject/voms-signing-subject";

    /** The ID of the subject attribute, {@value} , containing the DN of the signer of the VOMS service's certificate. */
    public final static String VOMS_SIGNER_ISSUER = "http://authz-interop.org/xacml/subject/voms-signing-issuer";

    /** The ID of the subject attribute, {@value} , containing the FQANs given in the VOMS attribute certificate. */
    public final static String VOMS_FQAN = "http://authz-interop.org/xacml/subject/voms-fqan";

    /** The ID of the subject attribute, {@value} , containing the primary FQAN given in the VOMS attribute certificate. */
    public final static String VOMS_PRIMARY_FQAN = "http://authz-interop.org/xacml/subject/primary-fqan";

    /**
     * The ID of the subject attribute, {@value} , containing the generic attributes given in the VOMS attribute
     * certificate.
     */
    public final static String VOMS_GA = "http://authz-interop.org/xacml/subject/generic-attribute";

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(X509PolicyInformationPoint.class);

    /** The id of this PIP */
    private String id;

    /** Trust manager used to validate an X.509 entity certificate. */
    private X509TrustManager certTrustManager;

    /** Certificate reader that is used to parse the certificate PEM into a certificate */
    private FileCertReader reader;

    /** Indicates whether VOMS, and hence attribute certificate, support is enabled. */
    private boolean vomsSupportEnabled;

    /** The trustStore used by voms validator. Make it instance variable to be able to stop the updater. */
    private PKIStore vomsStore;

    /**
     * The constructor for this PIP. This constructor disable VOMS support.
     * 
     * @param pipID ID of this PIP
     * @param trustManager trust manager used to validate the subject end entity certificate
     * 
     * @throws ConfigurationException thrown if the configuration of the PIP fails
     */
    public X509PolicyInformationPoint(String pipID, X509TrustManager trustManager) throws ConfigurationException {
        id = Strings.safeTrimOrNullString(pipID);
        if (id == null) {
            throw new ConfigurationException("Policy information point ID may not be null");
        }

        if (trustManager == null) {
            throw new ConfigurationException("Policy information point trust manager may not be null");
        }
        certTrustManager = trustManager;

        try {
            reader = new FileCertReader();
        } catch (CertificateException e) {
            throw new ConfigurationException("The certificate parser initialization failed: " + e.getMessage());
        }
    }

    /**
     * The constructor for this PIP. This constructor enables support for the VOMS attribute certificates.
     * 
     * @param pipID ID of this PIP
     * @param trustManager trust manager used to validate the subject end entity certificate
     * @param vomsDir path to the directory which contains the VOMS server .lsc files of certificates
     * 
     * @throws ConfigurationException thrown if the configuration of the PIP fails
     */
    public X509PolicyInformationPoint(String pipID, X509TrustManager trustManager, String vomsDir)
            throws ConfigurationException {
        this(pipID, trustManager);

        String vomsDirPath = null;
        try {
            vomsDirPath = Files.getFile(Strings.safeTrimOrNullString(vomsDir), false, true, true, false)
                    .getAbsolutePath();
            vomsStore = new PKIStore(vomsDirPath, PKIStore.TYPE_VOMSDIR);
            VOMSValidator.setTrustStore(vomsStore);
            vomsSupportEnabled = true;
        } catch (IOException e) {
            throw new ConfigurationException("VOMS directory file path " + vomsDir + " cannot be read", e);
        } catch (CertificateException e) {
            throw new ConfigurationException("Error processing certificates in VOMS directory  " + vomsDirPath, e);
        } catch (CRLException e) {
            throw new ConfigurationException("Error processing CRLs in VOMS directory " + vomsDirPath, e);
        }
    }

    /** {@inheritDoc} */
    public String getId() {
        return id;
    }

    /**
     * Gets whether VOMS support is enabled.
     * 
     * @return whether VOMS support is enabled
     */
    public boolean isVOMSSupportEnabled() {
        return vomsSupportEnabled;
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws AuthorizationServiceException {
        boolean pipApplied = false;

        X509Certificate[] certChain;
        X509Certificate endEntityCert;
        Collection<Attribute> attributes;
        for (Subject subject : request.getSubjects()) {
            certChain = getCertificateChain(subject);
            if (certChain == null) {
                continue;
            }

            endEntityCert = certChain[CertUtil.findClientCert(certChain)];
            String endEntitySubjectDN = endEntityCert.getSubjectX500Principal().getName(X500Principal.RFC2253);
            try {
                certTrustManager.checkClientTrusted(certChain, endEntityCert.getPublicKey().getAlgorithm());
            } catch (CertificateException e) {
                String errorMsg = "Certificate with subject DN " + endEntitySubjectDN + " failed PKIX validation";
                log.error(errorMsg, e);
                throw new AuthorizationServiceException(errorMsg, e);
            }

            log.debug("Extracting subject attributes from certificate with subject DN {}", endEntitySubjectDN);
            attributes = processCertChain(endEntityCert, certChain);
            if (attributes != null) {
                log.debug("Extracted subject attributes {} from certificate with subject DN {}", attributes,
                        endEntitySubjectDN);
                subject.getAttributes().addAll(attributes);
                pipApplied = true;
            }
        }

        return pipApplied;
    }

    /**
     * Gets the certificate chain for the subject's {@value #X509_CERT_CHAIN_ID} attribute.
     * 
     * @param subject subject from which to extract the certificate chain
     * 
     * @return the extracted certificate chain or null if the subject did not contain a chain of X.509 version 3
     *         certificates
     * 
     * @throws AuthorizationServiceException thrown if the subject contained more than one certificate chain or if the
     *             chain was not properly PEM encoded
     */
    private X509Certificate[] getCertificateChain(Subject subject) throws AuthorizationServiceException {
        String pemCertChain = null;

        for (Attribute attribute : subject.getAttributes()) {
            if (Strings.safeEquals(attribute.getId(), X509_CERT_CHAIN_ID)) {
                if (pemCertChain != null || attribute.getValues().size() < 1) {
                    String errorMsg = "Subject contains more than one X509 certificate chain.";
                    log.error(errorMsg);
                    throw new AuthorizationServiceException(errorMsg);
                }

                if (attribute.getValues().size() == 1) {
                    pemCertChain = Strings.safeTrimOrNullString((String) attribute.getValues().iterator().next());
                }
            }
        }

        if (pemCertChain == null) {
            return null;
        }

        BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(pemCertChain.getBytes()));
        Vector<X509Certificate> chainVector;
        try {
            chainVector = reader.readCertChain(bis);
        } catch (IOException e) {
            log.error("Unable to parse subject cert chain", e);
            throw new AuthorizationServiceException("Unable to parse subject cert chain", e);
        } finally {
            try {
                bis.close();
            } catch (IOException e) {
                log.error("Unable to close cert chain inputstream", e);
            }
        }

        X509Certificate[] certChain = chainVector.toArray(new X509Certificate[] {});
        for (X509Certificate cert : certChain) {
            if (cert.getVersion() != 3) {
                log.warn("Subject certificate {} is not a version 3 certificate, certificate chain ignored", cert
                        .getSubjectX500Principal().getName(X500Principal.RFC2253));
                return null;
            }
        }

        return certChain;
    }

    /**
     * Processes one certificate chain and adds the information to the subjects in the request.
     * 
     * @param endEntityCertificate end entity certificate for the subject currently being processed
     * @param certChain the certificate chain containing the end entity certificate from which information will be
     *            extracted
     */
    private Collection<Attribute> processCertChain(X509Certificate endEntityCertificate, X509Certificate[] certChain)
            throws AuthorizationServiceException {
        if (endEntityCertificate == null || certChain == null || certChain.length == 0) {
            return null;
        }

        log.debug("Extracting end-entity certificate attributes");
        HashSet<Attribute> subjectAttributes = new HashSet<Attribute>();
        String endEntityIssuerDn = endEntityCertificate.getIssuerX500Principal().getName(X500Principal.RFC2253);

        // get and set the subject DN attribute.
        String endEntitySubjectDN = endEntityCertificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
        Attribute attribute = new Attribute();
        attribute.setId(Attribute.ID_SUB_ID);
        attribute.setDataType(Attribute.DT_X500_NAME);
        attribute.setIssuer(endEntityIssuerDn);
        attribute.getValues().add(endEntitySubjectDN);
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // set the issuer DN attribute.
        attribute = new Attribute();
        attribute.setId(X509_DN_ISSUER);
        attribute.setDataType(Attribute.DT_X500_NAME);
        attribute.setIssuer(endEntityIssuerDn);
        attribute.getValues().add(endEntityIssuerDn);
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // set the cert serial number.
        attribute = new Attribute();
        attribute.setId(X509_SN);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.setIssuer(endEntityIssuerDn);
        attribute.getValues().add(endEntityCertificate.getSerialNumber().toString());
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        if (vomsSupportEnabled) {
            Collection<Attribute> vomsAttributes = processVOMS(endEntityCertificate, certChain);
            if (vomsAttributes != null) {
                subjectAttributes.addAll(vomsAttributes);
            }
        }

        return subjectAttributes;
    }

    /**
     * Processes the VOMS attributes and puts valid attributes into the subject object.
     * 
     * @param endEntityCert the end entity certificate for the subject being processed
     * @param certChain certificate chain containing the end entity certificate that contains the VOMS attribute
     *            certificate
     * 
     * @return the attributes extracted from the VOMS attribute certificate
     * 
     * @throws AuthorizationServiceException thrown if the end entity certificate contains more than one attribute
     *             certificate
     */
    @SuppressWarnings("unchecked")
    private Collection<Attribute> processVOMS(X509Certificate endEntityCert, X509Certificate[] certChain)
            throws AuthorizationServiceException {

        log.debug("Extracting VOMS attribute certificate attributes");
        VOMSValidator vomsValidator = null;
        try {
            vomsValidator = new VOMSValidator(certChain);
            vomsValidator.validate();

            // get attribute certificates
            List<VOMSAttribute> attributeCertificates = (List<VOMSAttribute>) vomsValidator.getVOMSAttributes();
            if (attributeCertificates == null || attributeCertificates.isEmpty()) {
                return null;
            }

            if (attributeCertificates.size() > 1) {
                String errorMsg = "End entity certificate for subject"
                        + endEntityCert.getSubjectX500Principal().getName(X500Principal.RFC2253)
                        + " contains more than one attribute certificate";
                log.error(errorMsg);
                throw new AuthorizationServiceException(errorMsg);
            }

            VOMSAttribute attributeCertificate = attributeCertificates.get(0);
            if (attributeCertificate == null) {
                return null;
            }

            HashSet<Attribute> vomsAttributes = new HashSet<Attribute>();

            Attribute voAttribute = new Attribute();
            voAttribute.setId(VOMS_VO);
            voAttribute.setDataType(Attribute.DT_STRING);
            voAttribute.setIssuer(attributeCertificate.getIssuerX509());
            voAttribute.getValues().add(attributeCertificate.getVO());
            log.debug("Extracted attribute: {}", voAttribute);
            vomsAttributes.add(voAttribute);

            List<FQAN> fqans = attributeCertificate.getListOfFQAN();
            if (fqans != null && !fqans.isEmpty()) {
                Attribute primaryFqanAttribute = new Attribute();
                primaryFqanAttribute.setDataType(VOMS_PRIMARY_FQAN);
                primaryFqanAttribute.setId(Attribute.DT_STRING);
                primaryFqanAttribute.setIssuer(attributeCertificate.getIssuerX509());
                primaryFqanAttribute.getValues().add(fqans.get(0).getFQAN());
                log.debug("Extracted attribute: {}", primaryFqanAttribute);
                vomsAttributes.add(primaryFqanAttribute);

                // handle rest of the fqans
                Attribute fqanAttribute = new Attribute();
                fqanAttribute.setId(VOMS_FQAN);
                fqanAttribute.setDataType(Attribute.DT_STRING);
                fqanAttribute.setIssuer(attributeCertificate.getIssuerX509());
                for (FQAN fqan : fqans) {
                    fqanAttribute.getValues().add(fqan.getFQAN());
                }
                log.debug("Extracted attribute: {}", fqanAttribute);
                vomsAttributes.add(fqanAttribute);
            }

            return vomsAttributes;
        } finally {
            if (vomsValidator != null) {
                log.debug("cleaning up VOMS validator");
                vomsValidator.cleanup();
            }
        }
    }

    /**
     * Used to stop any running threads invoked by this instance. E.g. the poller for changes in the vomsdir and trusted
     * CAs directory.
     */
    public void stop() {
        if (vomsSupportEnabled && vomsStore != null) {
            vomsStore.stopRefresh();
        }
    }

    /** {@inheritDoc} */
    public void start() throws AuthorizationServiceException {
        // nothing to do
    }
}