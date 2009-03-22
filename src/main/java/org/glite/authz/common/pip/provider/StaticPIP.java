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

package org.glite.authz.common.pip.provider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.util.Strings;

/** A PIP that provides a static set of attributes to a {@link Request}. */
@ThreadSafe
public class StaticPIP extends AbstractPolicyInformationPoint {

    /** String attribute data type URI. */
    private static final String DATA_TYPE = "http://www.w3.org/2001/XMLSchema#string";

    /** ID of this PIP. */
    private String id;

    /** Issuer of the attributes. */
    private String attributeIssuer;

    /** Action attributes to be added to the request. */
    private List<Attribute> actionAttributes;

    /** Environment attributes to be added to the request. */
    private List<Attribute> environmentAttributes;

    /** Resource attributes to be added to the request. */
    private List<Attribute> resourceAttributes;

    /** Subject attributes to be added to the request. */
    private List<Attribute> subjectAttributes;

    /**
     * Whether the given resource attributes should be added to every resource in the request. Default value:
     * <code>false</code>
     */
    private boolean addAttributesToAllResources;

    /**
     * Whether the given subject attributes should be added to every resource in the request. Default value:
     * <code>false</code>
     */
    private boolean addAttributesToAllSubjects;

    /**
     * Constructor.
     * 
     * @param pipID the ID of this PIP
     * @param action attributes to be added to the action attributes in the request
     * @param environment attributes to be added to the environment attributes in the request
     * @param resource attributes to be added to the resource attributes in the request
     * @param subject attributes to be added to the subject attributes in the request
     */
    public StaticPIP(String pipID, Map<String, List<String>> action, Map<String, List<String>> environment,
            Map<String, List<String>> resource, Map<String, List<String>> subject) {
        id = Strings.safeTrimOrNullString(pipID);
        if (id == null) {
            throw new IllegalArgumentException("PIP ID may not be null");
        }

        addAttributesToAllResources = false;
        addAttributesToAllSubjects = false;

        actionAttributes = mapToAttributes(action);
        environmentAttributes = mapToAttributes(environment);
        resourceAttributes = mapToAttributes(resource);
        subjectAttributes = mapToAttributes(subject);
    }

    /** {@inheritDoc} */
    public String getId() {
        return id;
    }

    /**
     * Gets the ID of the attribute issuer.
     * 
     * @return ID of the attribute issuer
     */
    public String getAttributeIssuer() {
        return attributeIssuer;
    }

    /**
     * Sets the ID of the attribute issuer.
     * 
     * @param issuer ID of the attribute issuer
     */
    public void setAttributeIssuer(String issuer) {
        attributeIssuer = Strings.safeTrimOrNullString(issuer);
    }

    /**
     * Whether resource attributes should be added to all resources within the request. If not, and there is more than
     * one resource in the request at the time the PIP is run, the PIP will error out.
     * 
     * @return whether resource attributes should be added to all resources within the request
     */
    public boolean isAddAttributesToAllResources() {
        return addAttributesToAllResources;
    }

    /**
     * Sets whether resource attributes should be added to all resources within the request.
     * 
     * @param addAll whether resource attributes should be added to all resources within the request
     */
    public void setAddAttributesToAllResources(boolean addAll) {
        addAttributesToAllResources = addAll;
    }

    /**
     * Whether subject attributes should be added to all subjects within the request. If not, and there is more than one
     * subject in the request at the time the PIP is run, the PIP will error out.
     * 
     * @return whether subject attributes should be added to all subject within the request
     */
    public boolean isAddAttributesToAllSubjects() {
        return addAttributesToAllSubjects;
    }

    /**
     * Sets whether subject attributes should be added to all subject within the request.
     * 
     * @param addAll whether subject attributes should be added to all subject within the request
     */
    public void setAddAttributesToAllSubjects(boolean addAll) {
        addAttributesToAllSubjects = addAll;
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws AuthorizationServiceException {
        Action action = request.getAction();
        if (action == null) {
            action = new Action();
            request.setAction(action);
        }
        action.getAttributes().addAll(actionAttributes);

        Environment environment = request.getEnvironment();
        if (environment == null) {
            environment = new Environment();
            request.setEnvironment(environment);
        }
        environment.getAttributes().addAll(environmentAttributes);

        if (!resourceAttributes.isEmpty()) {
            Set<Resource> resources = request.getResources();
            if (resources.size() > 1 && !addAttributesToAllResources) {
                throw new AuthorizationServiceException(
                        "More than one Resource present in request and PIP configured to only add attribues to a single Resource");
            }

            if (request.getResources().size() == 0) {
                request.getResources().add(new Resource());
            }

            for (Resource resource : resources) {
                resource.getAttributes().addAll(resourceAttributes);
            }
        }

        if (!subjectAttributes.isEmpty()) {
            Set<Subject> subjects = request.getSubjects();
            if (subjects.size() > 1 && !addAttributesToAllSubjects) {
                throw new AuthorizationServiceException(
                        "More than one Subject present in request and PIP configured to only add attribues to a single Subject");
            }

            if (request.getSubjects().size() == 0) {
                request.getSubjects().add(new Subject());
            }

            for (Subject subject : subjects) {
                subject.getAttributes().addAll(subjectAttributes);
            }
        }

        return true;
    }

    /**
     * Converts a map in to a list of {@link Attribute}s.
     * 
     * @param attributeMap map of attributes where the key is the attribute ID and the value is the list of attribute
     *            values
     * 
     * @return the list of {@link Attribute}s.
     */
    private List<Attribute> mapToAttributes(Map<String, List<String>> attributeMap) {
        ArrayList<Attribute> attributes = new ArrayList<Attribute>();

        if (attributeMap == null) {
            return attributes;
        }

        Attribute attribute;
        List<String> attributeValues;
        for (String attributeId : attributeMap.keySet()) {
            if (Strings.isEmpty(attributeId)) {
                continue;
            }

            attribute = new Attribute();
            attribute.setId(attributeId);
            attribute.setIssuer(attributeIssuer);
            attribute.setDataType(DATA_TYPE);

            attributeValues = attributeMap.get(attributeId);
            if (attributeValues != null) {
                for (String attributeValue : attributeValues) {
                    if (!Strings.isEmpty(attributeValue)) {
                        attribute.getValues().add(Strings.safeTrim(attributeValue));
                    }
                }
            }

            attributes.add(attribute);
        }

        return attributes;
    }
}