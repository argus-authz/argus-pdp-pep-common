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
package org.glite.authz.common.obligation.provider.dfpmap;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.obligation.AbstractObligationHandler;
import org.glite.authz.common.obligation.ObligationProcessingException;
import org.glite.authz.common.pip.provider.X509PIP;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class DFPMObligationHandler extends AbstractObligationHandler {
    
    /** The URI, {@value}, of the obligation used to indicate that an grid map based account mapping should occur. */
    public static final String MAPPING_OB_ID = "x-posix-account-map";

    /** The URI, {@value}, of the username obligation. */
    public static final String USERNAME_OB_ID = "http://authz-interop.org/xacml/obligation/username";

    /** The URI, {@value}, of the username obligation attribute. */
    public static final String USERNAME_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/username";

    /** The URI, {@value}, of the UID/GID obligation. */
    public static final String UIDGID_OB_ID = "http://authz-interop.org/xacml/obligation/uidgid";

    /** The URI, {@value}, of the secondary GIDs obligation. */
    public static final String SECONDARY_GIDS_OB_ID = "http://authz-interop.org/xacml/obligation/secondary-gids";

    /** The URI, {@value}, of the UID obligation attribute. */
    public static final String UID_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/posix-uid";

    /** The URI, {@value}, of the GID obligation attribute. */
    public static final String GID_ATTRIB_ID = "http://authz-interop.org/xacml/attribute/posix-gid";
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DFPMObligationHandler.class);
    
    /** DN/FQAN to POSIX account mapper. */
    private AccountMapper accountMapper;
    
    /**
     * Constructor.
     * 
     * @param obligationId ID of this obligation handler
     * @param mapper mapper used to map a subject to a POSIX account
     */
    public DFPMObligationHandler(String obligationId, AccountMapper mapper){
        super(MAPPING_OB_ID);
        
        if(mapper == null){
            throw new IllegalArgumentException("Account mapper may not be null");
        }
        accountMapper = mapper;
    }
    
    /**
     * Constructor.
     * 
     * @param obligationId ID of this obligation handler
     * @param precedence precendence of this obligation handler
     * @param mapper mapper used to map a subject to a POSIX account
     */
    public DFPMObligationHandler(String obligationId, int precedence, AccountMapper mapper){
        super(MAPPING_OB_ID, precedence);
        
        if(mapper == null){
            throw new IllegalArgumentException("Account mapper may not be null");
        }
        accountMapper = mapper;
    }

    /** {@inheritDoc} */
    public void evaluateObligation(Request request, Result result) throws ObligationProcessingException {
        Subject subject = getSubject(request);
        
        X500Principal subjectDN = getDN(subject);
        FQAN primaryFQAN = getPrimaryFQAN(subject);
        List<FQAN> secondaryFQANs = getSecondaryFQANs(subject);
        
        PosixAccount mappedAccount = accountMapper.mapToAccount(subjectDN, primaryFQAN, secondaryFQANs);
        if(mappedAccount != null){
            addUIDGIDObligations(result, mappedAccount);
            
            // Remove the mapping obligation (even if it appears multiple times) 
            // since we've handled it and replaced it with the username and uid/gid obligations
            Iterator<Obligation> obligationItr = result.getObligations().iterator();
            Obligation obligation;
            List<Obligation> removedObligations = new ArrayList<Obligation>();
            while(obligationItr.hasNext()){
                obligation = obligationItr.next();
                if(obligation.getId().equals(MAPPING_OB_ID)){
                    removedObligations.add(obligation);
                }
            }
            result.getObligations().removeAll(removedObligations);
        }
    }
    
    /**
     * Gets the subject from the request.
     * 
     * @param request authorization request
     * 
     * @return the subject of the request
     * 
     * @throws ObligationProcessingException thrown if there is more than one subject in the request
     */
    private Subject getSubject(Request request) throws ObligationProcessingException{
        Set<Subject> subjects = request.getSubjects();
        if(subjects == null || subjects.isEmpty()){
            throw new ObligationProcessingException("Unable to process request, it does not contain a subject");
        }
        if(subjects.size() != 1){
            log.warn("This obligation only operates on requests containing a single subject, this request contained {} subjects", subjects.size());
        }
        return subjects.iterator().next();
    }
    
    /**
     * Gets the subject's DN from the subject DN attribute.
     * 
     * @param dnAttribute subject DN attribute
     * 
     * @return the subject DN
     * 
     * @throws ObligationProcessingException thrown if the given attribute contains no values, is not of the right data type, or its value is not a valid DN
     */
    private X500Principal getDN(Subject subject) throws ObligationProcessingException{
        Attribute dnAttribute = null;
        
        for(Attribute attribute : subject.getAttributes()){
            if(attribute.getId().equals(Attribute.ID_SUB_ID)){
                log.debug("Extracted subject attribute from request: {}", attribute);
                dnAttribute = attribute;
                break;
            }
        }
        
        if(dnAttribute == null){
            log.error("Subject of the authorization request did not contain a subject ID attribute");
            throw new ObligationProcessingException("Invalid request, missing subject attribute");
        }
        
        if(!dnAttribute.getDataType().equals(Attribute.DT_X500_NAME)){
            log.error("Subject ID attribute of the authorization request was of the incorrect data type: {}", dnAttribute.getDataType());
            throw new ObligationProcessingException("Invalid request, subject attribute of invalid data type");
        }
        
        Set<?> values = dnAttribute.getValues();
        if(values == null || values.isEmpty()){
            log.error("Subject ID attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }
        
        if(values.size() > 1){
            log.warn("Subject ID attribute of the authroization request contains more than one value, only the first will be used");
        }
        
        try{
            return new X500Principal(values.iterator().next().toString());
        }catch(IllegalArgumentException e){
            log.error("Value of the Subject ID attribute of the authorization request was not a valid X.509 DN");
            throw new ObligationProcessingException("Invalid request, subject attribute value was invalid");
        }
    }
    
    private FQAN getPrimaryFQAN(Subject subject) throws ObligationProcessingException {
        Attribute primaryFQANAttribute = null;
        
        for(Attribute attribute : subject.getAttributes()){
            if(attribute.getId().equals(X509PIP.VOMS_PRIMARY_FQAN)){
                log.debug("Extracted primary FQAN attribute from request: {}", attribute);
                primaryFQANAttribute = attribute;
                break;
            }
        }
        
        if(primaryFQANAttribute == null){
            log.error("Subject of the authorization request did not contain a subject primary FQAN attribute");
            throw new ObligationProcessingException("Invalid request, missing subject attribute");
        }
        
        if(!primaryFQANAttribute.getDataType().equals(Attribute.DT_STRING)){
            log.error("Subject primary FQAN attribute of the authorization request was of the incorrect data type: {}", primaryFQANAttribute.getDataType());
            throw new ObligationProcessingException("Invalid request, subject attribute of invalid data type");
        }
        
        Set<?> values = primaryFQANAttribute.getValues();
        if(values == null || values.isEmpty()){
            log.error("Subject primary FQAN attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }
        
        if(values.size() > 1){
            log.warn("Subject primary FQAN attribute of the authroization request contains more than one value, only the first will be used");
        }
        
        try{
            return FQAN.parseFQAN(values.iterator().next().toString());
        }catch(IllegalArgumentException e){
            log.error("Value of the Subject primary FQAN attribute of the authorization request was not a valid FQAN");
            throw new ObligationProcessingException("Invalid request, subject attribute value was invalid");
        }
    }
    
    private List<FQAN> getSecondaryFQANs(Subject subject) throws ObligationProcessingException {
        Attribute secondaryFQANsAttribute = null;
        
        for(Attribute attribute : subject.getAttributes()){
            if(attribute.getId().equals(X509PIP.VOMS_FQAN)){
                log.debug("Extracted secondary FQAN attribute from request: {}", attribute);
                secondaryFQANsAttribute = attribute;
                break;
            }
        }
        
        if(secondaryFQANsAttribute == null){
            log.error("Subject of the authorization request did not contain a subject secondary FQAN attribute");
            throw new ObligationProcessingException("Invalid request, missing subject attribute");
        }
        
        if(!secondaryFQANsAttribute.getDataType().equals(Attribute.DT_STRING)){
            log.error("Subject secondary FQAN attribute of the authorization request was of the incorrect data type: {}", secondaryFQANsAttribute.getDataType());
            throw new ObligationProcessingException("Invalid request, subject attribute of invalid data type");
        }
        
        Set<?> values = secondaryFQANsAttribute.getValues();
        if(values == null || values.isEmpty()){
            log.error("Subject secondary FQAN attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }
        
        if(values.size() > 1){
            log.warn("Subject secondary FQAN attribute of the authroization request contains more than one value, only the first will be used");
        }
        
        ArrayList<FQAN> secondaryFQANs = new ArrayList<FQAN>();
        try{
            Iterator<?> valueItr = values.iterator();
            while(valueItr.hasNext()){
                secondaryFQANs.add(FQAN.parseFQAN(valueItr.next().toString()));
            }
            return secondaryFQANs;
        }catch(IllegalArgumentException e){
            log.error("Value of the Subject secondary FQAN attribute of the authorization request was not a valid FQAN");
            throw new ObligationProcessingException("Invalid request, subject attribute value was invalid");
        }
    }
    
    /**
     * Adds the UID/GID and username obligations to a result.
     * 
     * @param result current result
     * @param account account whose information will be added as obligations
     */
    protected void addUIDGIDObligations(Result result, PosixAccount account) {
        Obligation mappingOb = null;
        for (Obligation ob : result.getObligations()) {
            if (ob.getId().equals(MAPPING_OB_ID)) {
                mappingOb = ob;
            }
        }
        result.getObligations().remove(mappingOb);

        Obligation usernameOb = buildUsernameObligation(account);
        if (usernameOb != null) {
            result.getObligations().add(usernameOb);
        }

        Obligation uidgidOb = buildUIDGIDObligation(account);
        result.getObligations().add(uidgidOb);

        Obligation secondaryGIDs = buildSecondaryGIDsObligation(account);
        if (secondaryGIDs != null) {
            result.getObligations().add(secondaryGIDs);
        }
    }

    /**
     * Creates an {@value #USERNAME_OB_ID} obligation if the given {@link PosixAccount} provides a username.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation or null if the {@link PosixAccount} did not contain a username
     */
    protected Obligation buildUsernameObligation(PosixAccount account) {
        String username = Strings.safeTrimOrNullString(account.getLoginName());
        if (username == null) {
            return null;
        }

        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(USERNAME_OB_ID);

        AttributeAssignment attributeAssignment = new AttributeAssignment();
        attributeAssignment.setAttributeId(USERNAME_ATTRIB_ID);
        attributeAssignment.getValues().add(username);
        obligation.getAttributeAssignments().add(attributeAssignment);

        return obligation;
    }

    /**
     * Creates an {@value #UIDGID_OB_ID} obligation with information in the given {@link PosixAccount}.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation
     */
    protected Obligation buildUIDGIDObligation(PosixAccount account) {
        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(UIDGID_OB_ID);

        AttributeAssignment attributeAssignment = new AttributeAssignment();
        attributeAssignment.setAttributeId(UID_ATTRIB_ID);
        attributeAssignment.getValues().add(Long.toString(account.getUid()));
        obligation.getAttributeAssignments().add(attributeAssignment);

        PosixAccount.Group primaryGroup = account.getPrimaryGroup();
        if (primaryGroup != null) {
            attributeAssignment = new AttributeAssignment();
            attributeAssignment.setAttributeId(GID_ATTRIB_ID);
            attributeAssignment.getValues().add(primaryGroup.getName());
            obligation.getAttributeAssignments().add(attributeAssignment);
        }

        return obligation;
    }

    /**
     * Creates an {@value #SECONDARY_GIDS_OB_ID} obligation if the given {@link PosixAccount} has more than one GID.
     * 
     * @param account the account used to populate the obligation
     * 
     * @return the created obligation or null if the {@link PosixAccount} did not contain a username
     */
    protected Obligation buildSecondaryGIDsObligation(PosixAccount account) {
        List<PosixAccount.Group> secondaryGroups = account.getSecondaryGroups();
        if (secondaryGroups == null) {
            return null;
        }
        
        Obligation obligation = new Obligation();
        obligation.setFulfillOn(Result.DECISION_PERMIT);
        obligation.setId(SECONDARY_GIDS_OB_ID);

        AttributeAssignment attributeAssignment;
        for(PosixAccount.Group secondaryGroup : secondaryGroups){
            attributeAssignment = new AttributeAssignment();
            attributeAssignment.setAttributeId(GID_ATTRIB_ID);
            attributeAssignment.getValues().add(secondaryGroup.getName());
            obligation.getAttributeAssignments().add(attributeAssignment);
        }

        return obligation;
    }
}