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
package org.glite.authz.common.context;

import java.security.NoSuchAlgorithmException;

import org.glite.authz.common.AuthzServiceConstants;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;

/**
 * Helper class for the XACML decision request message context
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class DecisionRequestContextHelper {

    /** Generator for message IDs. */
    private static IdentifierGenerator idGenerator;

    /** Builder of XACMLAuthzDecisionQuery XMLObjects. */
    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<XACMLAuthzDecisionQueryType> authzDecisionQueryBuilder= (SAMLObjectBuilder<XACMLAuthzDecisionQueryType>) Configuration.getBuilderFactory().getBuilder(XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);

    /** Builder of Body XMLObjects. */
    @SuppressWarnings("unchecked")
    private static SOAPObjectBuilder<Body> bodyBuilder= (SOAPObjectBuilder<Body>) Configuration.getBuilderFactory().getBuilder(Body.TYPE_NAME);

    /** Builder of Envelope XMLObjects. */
    @SuppressWarnings("unchecked")
    private static SOAPObjectBuilder<Envelope> envelopeBuilder= (SOAPObjectBuilder<Envelope>) Configuration.getBuilderFactory().getBuilder(Envelope.TYPE_NAME);

    /** Builder of Issuer XMLObjects. */
    @SuppressWarnings("unchecked")
    private static SAMLObjectBuilder<Issuer> issuerBuilder= (SAMLObjectBuilder<Issuer>) Configuration.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    static {
        try {
            idGenerator= new SecureRandomIdentifierGenerator();
            idGenerator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            // do nothing, all VMs are required to support the default algo
        }
    }

    /**
     * Builds a {@link DecisionRequestContext}. The communication profileID used
     * is {@value AuthzServiceConstants#XACML_SAML_PROFILE_URI}.
     * 
     * @param messageIssuerId
     *            The entityID of the message issuer
     * @return the {@link DecisionRequestContext}
     */
    static public DecisionRequestContext buildMessageContext(
            String messageIssuerId) {
        DecisionRequestContext messageContext= new DecisionRequestContext();
        messageContext.setCommunicationProfileId(AuthzServiceConstants.XACML_SAML_PROFILE_URI);
        messageContext.setOutboundMessageIssuer(messageIssuerId);
        messageContext.setSOAPRequestParameters(new HttpSOAPRequestParameters("http://www.oasis-open.org/committees/security"));

        // TODO fill in security policy resolver
        return messageContext;
    }

    /**
     * Creates a SOAP message within which lies the XACML request and set it as
     * outbound message in the message context.
     * 
     * @param messageIssuerId
     *            The entityID of the message issuer
     * @param messageContext
     *            current request context
     * @param xacmlRequest
     *            the XACML authorization request to be sent
     * 
     * @return the generated SOAP envelope containing the message
     */
    static public Envelope buildSOAPMessage(String messageIssuerId,
            DecisionRequestContext messageContext, RequestType xacmlRequest) {

        // create SAML decision query request
        XACMLAuthzDecisionQueryType samlRequest= authzDecisionQueryBuilder.buildObject(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20,
                                                                                       XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);
        samlRequest.setRequest(xacmlRequest);

        Issuer issuer= issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(messageIssuerId);
        samlRequest.setIssuer(issuer);

        samlRequest.setID(idGenerator.generateIdentifier());
        samlRequest.setIssueInstant(new DateTime());

        samlRequest.setInputContextOnly(false);
        samlRequest.setReturnContext(true);

        // create SOAP body and envelop
        Body body= bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlRequest);

        Envelope envelope= envelopeBuilder.buildObject();
        envelope.setBody(body);

        // attach the SOAP envelop to message context 
        messageContext.setOutboundMessage(envelope);
        messageContext.setOutboundMessageId(samlRequest.getID());

        return envelope;
    }

}
