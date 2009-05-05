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

package org.glite.authz.common.obligation.provider.gridmap;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.glite.authz.common.obligation.provider.gridmap.GridMap.GridMapKeyMatchFunction;
import org.glite.authz.common.util.Strings;

/** A FQAN (fully qualified attribute name). */
public class FQAN implements GridMapKey {

    /** The allowed characters in the components of an FQAN (group component ID, attribute ID, and attribute value). */
    public final static String fqanComponentCharactersRegex = "[_\\w\\.\\-\\*]+";

    /** ID of the {@value} attribute. */
    public final static String ROLE_ATTRIB_ID = "Role";

    /** ID of the {@value} attribute. */
    public final static String CAPABILITY_ATTRIB_ID = "Capability";

    /** The group component of the FQAN. */
    private String attributeGroupId;

    /** The role component of the FQAN. */
    private Map<String, Attribute> attributes;

    /**
     * Constructor.
     * 
     * @param groupId the ID of the attribute group
     * @param groupAttributes the attributes in the group
     */
    public FQAN(String groupId, Collection<Attribute> groupAttributes) {
        attributeGroupId = groupId;

        if (groupAttributes != null) {
            TreeMap<String, Attribute> modifiableAttributes = new TreeMap<String, Attribute>();
            for (Attribute attribute : groupAttributes) {
                modifiableAttributes.put(attribute.getId(), attribute);
            }
            attributes = Collections.unmodifiableMap(modifiableAttributes);
        } else {
            attributes = Collections.EMPTY_MAP;
        }
    }

    /**
     * Gets the ID of the attribute group.
     * 
     * @return ID of the attribute group
     */
    public String getAttributeGroupId() {
        return attributeGroupId;
    }

    /**
     * Gets the attributes.
     * 
     * @return the attributes
     */
    public Collection<Attribute> getAttributes() {
        return attributes.values();
    }

    /**
     * Gets an attribute by its ID.
     * 
     * @param id id of the attribute
     * 
     * @return the attribute with the given ID or null if there is no attribute with that ID
     */
    public Attribute getAttributeById(String id) {
        return attributes.get(id);
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder fqanStr = new StringBuilder(getAttributeGroupId());

        Attribute attribute;
        for (String id : attributes.keySet()) {
            attribute = attributes.get(id);
            fqanStr.append("/").append(attribute.getId());
            fqanStr.append("=").append(attribute.getValue());
        }

        return fqanStr.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return toString().hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        
        if(obj == null){
            return false;
        }

        if (obj instanceof FQAN) {
            FQAN otherFQAN = (FQAN) obj;
            return getAttributeGroupId().equals(otherFQAN.getAttributeGroupId())
                    && getAttributes().equals(otherFQAN.getAttributes());
        }

        return false;
    }

    /** An attribute with an FQAN. */
    public static class Attribute {

        /** The string representing a null value, {@value} . */
        public final static String NULL_VALUE = "NULL";

        /** The ID of the attribute. */
        private String id;

        /** The value of the attribute. */
        private String value;

        /**
         * Constructor.
         * 
         * @param attributeId ID of the attribute
         * @param attributeValue value of the attribute
         */
        private Attribute(String attributeId, String attributeValue) {
            id = attributeId;
            value = attributeValue;
        }

        /**
         * Parses an FQAN attribute string. An FQAN attribute string takes the format {@literal <id>=<value>} where the
         * both the id and value contain only a-z, A-Z, underscore, hyphen, period, and asterisk characters. The value
         * must contain at least on of the allowed characters, the value must contain zero or more allowed characters.
         * If no characters are included in the value of the attribute is considered to be the null value
         * {@value #NULL_VALUE}.
         * 
         * @param attributeString the string to parse
         * 
         * @return the constructed attribute
         * 
         * @throws IllegalKeyFormatException thrown if the FQAN contains illegal characters or is not in the proper
         *             {@literal <id>=<value>} format
         */
        public static Attribute parse(String attributeString) throws IllegalKeyFormatException {
            if (!attributeString.contains("=")) {
                throw new IllegalKeyFormatException("FQAN attribute " + attributeString
                        + " does not contain an equals sign");
            }

            String[] components = attributeString.split("=");

            String id = Strings.safeTrim(components[0]);
            if (!id.matches(fqanComponentCharactersRegex)) {
                throw new IllegalKeyFormatException("FQAN attribute " + attributeString
                        + " contains illegal characters within its id");
            }

            String value;
            if (components.length == 1) {
                value = NULL_VALUE;
            } else {
                value = Strings.safeTrimOrNullString(components[1]);
                if (value.equals("NULL")) {
                    value = NULL_VALUE;
                } else {
                    if (!value.matches(fqanComponentCharactersRegex)) {
                        throw new IllegalKeyFormatException("FQAN attribute " + attributeString
                                + " contains illegal characters within its value");
                    }
                }
            }

            return new Attribute(id, value);
        }

        /**
         * Gets the ID of the attribute.
         * 
         * @return ID of the attribute
         */
        public String getId() {
            return id;
        }

        /**
         * Gets the value of the attribute.
         * 
         * @return value of the attribute
         */
        public String getValue() {
            return value;
        }
    }

    /** A {@link GridMapKeyMatchFunction} for {@link FQAN} objects. */
    public static class MatchFunction implements GridMapKeyMatchFunction {

        /** {@inheritDoc} */
        public boolean matches(GridMapKey target, GridMapKey candidate) {
            if (target instanceof FQAN && candidate instanceof FQAN) {
                FQAN targetFQAN = (FQAN) target;
                FQAN candidateFQAN = (FQAN) candidate;

                String targetGroupIDRegex = targetFQAN.getAttributeGroupId().replace("*", ".+");
                if (!candidateFQAN.getAttributeGroupId().matches(targetGroupIDRegex)) {
                    return false;
                }

                Attribute candidateAttribute;
                for (Attribute requiredAttribute : targetFQAN.getAttributes()) {
                    candidateAttribute = candidateFQAN.getAttributeById(requiredAttribute.getId());
                    if(candidateAttribute == null){
                        if(requiredAttribute.getValue().equals(Attribute.NULL_VALUE)){
                            return true;
                        }
                        return false;
                    }

                    if (!attributeMatches(requiredAttribute, candidateAttribute)) {
                        return false;
                    }
                }

                return true;
            }

            return false;
        }

        /**
         * Checks whether an attribute matches another attribute.
         * 
         * @param target the attribute the candidate is checked against
         * @param candidate the attribute checked against the target
         * 
         * @return true if the candidate matches the target, false if not
         */
        private boolean attributeMatches(Attribute target, Attribute candidate) {
            if (!target.getId().equals(candidate.getId())) {
                return false;
            }

            if (target.getValue().equals(Attribute.NULL_VALUE)) {
                return true;
            }

            String valueMatch = target.getValue().replace("*", ".+");
            return candidate.getValue().matches(valueMatch);
        }
    }
}