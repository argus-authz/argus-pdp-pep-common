/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.pip.PIPProcessingException;
import org.glite.authz.common.util.Strings;
import org.glite.security.util.CertUtil;
import org.glite.security.util.FileCertReader;
import org.glite.voms.FQAN;
import org.glite.voms.PKIStore;
import org.glite.voms.PKIUtils;
import org.glite.voms.PKIVerifier;
import org.glite.voms.VOMSAttribute;
import org.glite.voms.VOMSValidator;
import org.glite.voms.ac.ACValidator;
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
public class X509PIP extends AbstractPolicyInformationPoint {

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate processed by the PIP. */
    public static final String X509_CERT_CHAIN_ID = "http://authz-interop.org/xacml/subject/cert-chain";

    /**
     * The ID of the subject attribute, {@value} , containing the end-entity certificate's issuer's DN in the
     * non-standard OpenSSL format.
     */
    public static final String SUBJECT_X509_ID = "http://authz-interop.org/xacml/subject/subject-x509-id";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's issuer's DN. */
    public static final String X509_DN_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's serial number. */
    public static final String X509_SN = "http://authz-interop.org/xacml/subject/certificate-serial-number";

    /** The ID of the subject attribute, {@value} , containing the VO given in the VOMS attribute certificate. */
    public static final String VOMS_VO = "http://authz-interop.org/xacml/subject/vo";

    /**
     * The ID of the subject attribute, {@value} , containing the DN of the VOMS service that signed the VOMS attribute
     * certificate.
     */
    public static final String VOMS_SIGNER = "http://authz-interop.org/xacml/subject/voms-signing-subject";

    /** The ID of the subject attribute, {@value} , containing the DN of the signer of the VOMS service's certificate. */
    public static final String VOMS_SIGNER_ISSUER = "http://authz-interop.org/xacml/subject/voms-signing-issuer";

    /** The ID of the subject attribute, {@value} , containing the FQANs given in the VOMS attribute certificate. */
    public static final String VOMS_FQAN = "http://authz-interop.org/xacml/subject/voms-fqan";

    /** The ID of the subject attribute, {@value} , containing the primary FQAN given in the VOMS attribute certificate. */
    public static final String VOMS_PRIMARY_FQAN = "http://authz-interop.org/xacml/subject/voms-primary-fqan";

    /**
     * The ID of the subject attribute, {@value} , containing the generic attributes given in the VOMS attribute
     * certificate.
     */
    public static final String VOMS_GA = "http://authz-interop.org/xacml/subject/generic-attribute";

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(X509PIP.class);

    /** Reads a set of certificates in to a chain of {@link X509Certificate} objects. */
    private FileCertReader certReader;

    /** Whether the given cert chain must contain a proxy certificate in order to be valid. */
    private boolean requireProxyCertificate;
    
    /** Whether to perform PKIX validation on the incoming certificate. */
    private boolean performPKIXValidation;

    /** Whether VOMS AC support is currently enabled. */
    private boolean vomsSupportEnabled;

    /** Verifier used to validate an X.509 certificate chain which may, or may not, include AC certs. */
    private PKIVerifier certVerifier;

    /**
     * The constructor for this PIP. This constructor enables support for the VOMS attribute certificates.
     * 
     * @param pipID ID of this PIP
     * @param requireProxy whether a subject's certificate chain must require a proxy in order to be valid
     * @param eeTrustMaterial trust material used to validate the subject's end entity certificate
     * @param acTrustMaterial trust material used to validate the subject's attribute certificate certificate, may be
     *            null of AC support is not desired
     * 
     * @throws ConfigurationException thrown if the configuration of the PIP fails
     */
    public X509PIP(String pipID, boolean requireProxy, PKIStore eeTrustMaterial, PKIStore acTrustMaterial) throws ConfigurationException {
        super(pipID);

        requireProxyCertificate = requireProxy;
        
        if (eeTrustMaterial == null) {
            throw new ConfigurationException("Policy information point trust material may not be null");
        }

        if (acTrustMaterial == null) {
            vomsSupportEnabled = false;
        } else {
            vomsSupportEnabled = true;
        }

        try {
            certReader = new FileCertReader();
            certVerifier = new PKIVerifier(acTrustMaterial, eeTrustMaterial);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to create X509 trust manager: " + e.getMessage());
        }
    }

    /**
     * Gets whether VOMS support is enabled.
     * 
     * @return whether VOMS support is enabled
     */
    public boolean isVOMSSupportEnabled() {
        return vomsSupportEnabled;
    }

    /**
     * Gets whether the PKIX validation is performed against the processed cert chain.
     * 
     * @return whether the PKIX validation is performed against the processed cert chain
     */
    public boolean performsPKIXValidation() {
        return performPKIXValidation;
    }

    /**
     * Sets whether the PKIX validation is performed against the processed cert chain.
     * 
     * @param perform whether the PKIX validation is performed against the processed cert chain
     */
    public void performPKIXValidation(boolean perform) {
        performPKIXValidation = perform;
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws PIPProcessingException {
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
            if (performPKIXValidation && !certVerifier.verify(certChain)) {
                String errorMsg = "Certificate with subject DN " + endEntitySubjectDN + " failed PKIX validation";
                log.error(errorMsg);
                throw new PIPProcessingException(errorMsg);
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
     * @throws PIPProcessingException thrown if the subject contained more than one certificate chain or if the
     *             chain was not properly PEM encoded
     */
    private X509Certificate[] getCertificateChain(Subject subject) throws PIPProcessingException {
        String pemCertChain = null;

        for (Attribute attribute : subject.getAttributes()) {
            if (Strings.safeEquals(attribute.getId(), X509_CERT_CHAIN_ID)) {
                if (pemCertChain != null || attribute.getValues().size() < 1) {
                    String errorMsg = "Subject contains more than one X509 certificate chain.";
                    log.error(errorMsg);
                    throw new PIPProcessingException(errorMsg);
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
            chainVector = certReader.readCertChain(bis);
        } catch (IOException e) {
            log.error("Unable to parse subject cert chain", e);
            throw new PIPProcessingException("Unable to parse subject cert chain", e);
        } finally {
            try {
                bis.close();
            } catch (IOException e) {
                log.error("Unable to close cert chain inputstream", e);
            }
        }

        X509Certificate[] certChain = chainVector.toArray(new X509Certificate[] {});
        boolean proxyPresent = false;
        for (X509Certificate cert : certChain) {
            if (cert.getVersion() != 3) {
                log.warn("Subject certificate {} is not a version 3 certificate, certificate chain ignored", cert
                        .getSubjectX500Principal().getName(X500Principal.RFC2253));
                return null;
            }
            if(requireProxyCertificate && PKIUtils.isProxy(cert)){
                proxyPresent = true;
            }
        }

        if(requireProxyCertificate && !proxyPresent){
            return null;
        }
        
        return certChain;
    }

    /**
     * Processes one certificate chain and adds the information to the subjects in the request.
     * 
     * @param endEntityCertificate end entity certificate for the subject currently being processed
     * @param certChain the certificate chain containing the end entity certificate from which information will be
     *            extracted
     *
     * @return the attribute extracted from the certificate chain 
     * 
     * @throws PIPProcessingException thrown if there is a problem reading the information from the certificate chain
     */
    private Collection<Attribute> processCertChain(X509Certificate endEntityCertificate, X509Certificate[] certChain)
            throws PIPProcessingException {
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

        if (isVOMSSupportEnabled()) {
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
     * @throws PIPProcessingException thrown if the end entity certificate contains more than one attribute
     *             certificate
     */
    @SuppressWarnings("unchecked")
    private Collection<Attribute> processVOMS(X509Certificate endEntityCert, X509Certificate[] certChain)
            throws PIPProcessingException {

        log.debug("Extracting VOMS attribute certificate attributes");
        VOMSValidator vomsValidator = null;
        vomsValidator = new VOMSValidator(certChain, new ACValidator(certVerifier));
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
            throw new PIPProcessingException(errorMsg);
        }

        VOMSAttribute attributeCertificate = attributeCertificates.get(0);
        if (attributeCertificate == null) {
            return null;
        }

        HashSet<Attribute> vomsAttributes = new HashSet<Attribute>();

        Attribute voAttribute = new Attribute();
        voAttribute.setId(VOMS_VO);
        voAttribute.setDataType(Attribute.DT_STRING);
        voAttribute.setIssuer(attributeCertificate.getIssuer());
        voAttribute.getValues().add(attributeCertificate.getVO());
        log.debug("Extracted attribute: {}", voAttribute);
        vomsAttributes.add(voAttribute);

        List<FQAN> fqans = attributeCertificate.getListOfFQAN();
        if (fqans != null && !fqans.isEmpty()) {
            Attribute primaryFqanAttribute = new Attribute();
            primaryFqanAttribute.setId(VOMS_PRIMARY_FQAN);
            primaryFqanAttribute.setDataType(Attribute.DT_STRING);
            primaryFqanAttribute.setIssuer(attributeCertificate.getIssuer());
            primaryFqanAttribute.getValues().add(fqans.get(0).getFQAN());
            log.debug("Extracted attribute: {}", primaryFqanAttribute);
            vomsAttributes.add(primaryFqanAttribute);

            // handle rest of the fqans
            Attribute fqanAttribute = new Attribute();
            fqanAttribute.setId(VOMS_FQAN);
            fqanAttribute.setDataType(Attribute.DT_STRING);
            fqanAttribute.setIssuer(attributeCertificate.getIssuer());
            for (FQAN fqan : fqans) {
                fqanAttribute.getValues().add(fqan.getFQAN());
            }
            log.debug("Extracted attribute: {}", fqanAttribute);
            vomsAttributes.add(fqanAttribute);
        }

        return vomsAttributes;
    }
}