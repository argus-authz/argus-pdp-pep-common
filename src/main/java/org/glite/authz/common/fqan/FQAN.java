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

package org.glite.authz.common.fqan;

import java.text.ParseException;

import org.glite.authz.common.util.Strings;

/** Represents an FQAN. */
public class FQAN {

    /** Role component identifier, {@value} . */
    public static final String ROLE = "Role";

    /** Capability component identifier, {@value} . */
    public static final String CAPABILITY = "Capability";

    /** The value "NULL", used in the canonical form to represent the absence of a Role or Capability. */
    public static final String NULL = "NULL";
    
    /** The wildcard <code>*</code> used for pattern matching */
    public static final String WILDCARD = "*";

    /** Group name component of the FQAN. */
    private String groupName;

    /** Role component of the FQAN. */
    private String role;

    /** Capability component of the FQAN. */
    private String capability;

    /**
     * Constructor.
     * 
     * @param fqanGroupName group name of the FQAN, may not be null
     * @param fqanRole role value of the FQAN, may be null
     * @param fqanCapability capability value of the FQAN, may be null
     */
    public FQAN(String fqanGroupName, String fqanRole, String fqanCapability) {
        groupName = Strings.safeTrimOrNullString(fqanGroupName);
        if (groupName == null) {
            throw new IllegalArgumentException("Group name may not be null");
        }
        // remove trailing / in group name
        if (groupName.endsWith("/")) {
            groupName = groupName.substring(0, groupName.length() - 1);
        }

        role = Strings.safeTrimOrNullString(fqanRole);
        if (role == null || role.equalsIgnoreCase(NULL)) {
            role = NULL;
        }

        capability = Strings.safeTrimOrNullString(fqanCapability);
        if (capability == null || capability.equalsIgnoreCase(NULL)) {
            capability = NULL;
        }
    }

    /**
     * Constructor with a FQAN group name and a Role value.
     * 
     * @param fqanGroupName group name of the FQAN, may not be null
     * @param fqanRole role value of the FQAN, may be null
     */
    public FQAN(String fqanGroupName, String fqanRole) {
        this(fqanGroupName, fqanRole, null);
    }

    /**
     * Constructor with a FQAN group name, but without Role (NULL).
     * 
     * @param fqanGroupName group name of the FQAN, may not be null
     */
    public FQAN(String fqanGroupName) {
        this(fqanGroupName, null, null);
    }

    /**
     * Gets the group name component of the FQAN.
     * 
     * @return group name component of the FQAN
     */
    public String getGroupName() {
        return groupName;
    }

    /**
     * Gets the Role value of the FQAN i.e. <code>/Role=value</code>.
     * 
     * @return Role component of the FQAN
     */
    public String getRole() {
        return role;
    }

    /**
     * Gets the Capability value of the FQAN i.e <code>/Capability=value</code>.
     * 
     * @return Capability component of the FQAN
     */
    public String getCapability() {
        return capability;
    }

    /**
     * Parses an FQAN, in string form, in to an {@link FQAN}.
     * 
     * @param fqan FQAN in string form
     * 
     * @return FQAN object
     * 
     * @throws ParseException thrown if the FQAN string is invalid
     */
    public static FQAN parseFQAN(String fqan) throws ParseException {
        String trimmed = Strings.safeTrimOrNullString(fqan);
        if (trimmed == null) {
            return null;
        }

        if (!trimmed.startsWith("/")) {
            throw new ParseException("FQANs must start with a /", 0);
        }

        String[] components = trimmed.split("/");
        String[] subComponents;
        StringBuilder groupName = new StringBuilder();
        String role = null;
        String capability = null;
        for (String component : components) {
            if (component.contains("=")) {
                subComponents = component.split("=");
                if (subComponents.length == 1) {
                    continue;
                }

                if (subComponents.length > 2) {
                    throw new ParseException("Non group name components may not contain an = in their value: "
                            + component, fqan.indexOf(component));
                }

                if (subComponents[0].equalsIgnoreCase(ROLE)) {
                    if (role != null) {
                        throw new ParseException("Role may not appear more than once in an FQAN",
                                fqan.indexOf(component));
                    }
                    role = subComponents[1];
                } else if (subComponents[0].equalsIgnoreCase(CAPABILITY)) {
                    if (capability != null) {
                        throw new ParseException("Capability may not appear more than once in an FQAN",
                                fqan.indexOf(component));
                    }
                    capability = subComponents[1];
                } else {
                    throw new ParseException("FQAN contains an unknown, non-group-name component: " + component,
                            fqan.indexOf(component));
                }
            } else {
                if (!Strings.isEmpty(component)) {
                    groupName.append("/").append(component);
                }
            }
        }

        if (groupName.length() == 0) {
            throw new ParseException("FQAN did not contain a group name", 0);
        }

        return new FQAN(groupName.toString(), role, capability);
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(groupName);
        if (!role.equalsIgnoreCase(NULL)) {
            sb.append('/').append(ROLE).append('=').append(role);
        }
        if (!capability.equalsIgnoreCase(NULL)) {
            sb.append('/').append(CAPABILITY).append('=').append(capability);
        }
        return sb.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + groupName.hashCode();
        result = prime * result + role.hashCode();
        result = prime * result + capability.hashCode();
        return result;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (this == obj) {
            return true;
        }

        FQAN otherFQAN = (FQAN) obj;
        return getGroupName().equals(otherFQAN.getGroupName()) && getRole().equals(otherFQAN.getRole())
                && getCapability().equals(otherFQAN.getCapability());
    }

    /**
     * Checks whether this FQAN matches the given FQAN regular expression.
     * 
     * @param regexp the FQAN regular expression
     * 
     * @return true if the FQAN matches the regular expression.
     * 
     * @throws ParseException thrown if the given expression is not a valid FQAN regular expression
     * 
     * @see <a href="https://edms.cern.ch/file/975443/1/EGEE-III-JRA1_FQAN_wildcard_v1.0.pdf">FQAN matching
     *      specification</a>
     */
    public boolean matches(String regexp) throws ParseException {
        FQAN regexpFQAN = FQAN.parseFQAN(regexp);
        return matchesGroupName(regexpFQAN) && matchesRole(regexpFQAN);
    }

    public boolean matches(FQAN regexpFQAN) throws ParseException {
        return matchesGroupName(regexpFQAN) && matchesRole(regexpFQAN);
    }
    
    
    /**
     * Checks if the group name of this FQAN matches a group name regular expression. In the event that the expression
     * does not contain the wildcard '*' character, exact equality matching is performed
     * 
     * @param regexpFQAN the group name regular expression
     * 
     * @return true if the given group name matches the given regular expression
     * 
     * @throws ParseException thrown if the regular expression is not valid
     */
    protected boolean matchesGroupName(FQAN regexpFQAN) throws ParseException {
        String regexpGroup = regexpFQAN.getGroupName();
        if (regexpGroup.contains(WILDCARD)) {
            // group name contains a regular expression
            String groupNameBase = regexpGroup.substring(0, regexpGroup.length() - 1);
            if (!groupNameBase.endsWith("/")) {
                throw new ParseException(
                        "Invalid regular expression within FQAN group name, name does not end with a '/*'",
                        regexpGroup.length());
            }
            if (groupNameBase.contains(WILDCARD)) {
                throw new ParseException(
                        "Invalid regular expression within FQAN group name, name contains more than one '*'",
                        regexpGroup.indexOf(WILDCARD));
            }
            if (groupNameBase.equals("/")) {
                throw new ParseException(
                        "Invalid regular expression within FQAN group name, VO not specified", 0);
            }

            // we explicitly terminate this FQAN's group name so that we can easily compare
            // against the regexp strings, which are terminated, the alternative would have
            // been to strip off the terminator from the regexp string but that leads to problems
            // ie. '/foo/* would match '/foobar'
            String terminatedGroupName = groupName + "/";
            return terminatedGroupName.startsWith(groupNameBase);
        }

        // group name does not contain a regular expression
        return regexpGroup.equals(groupName);
    }

    /**
     * Checks if the role of this FQAN matches a role regular expression. In the event that the expression does not
     * contain the wildcard '*' character, exact equality matching is performed
     * 
     * @param regexpFQAN the role regular expression
     * 
     * @return true if the given role matches the given regular expression
     * 
     * @throws ParseException thrown if the regular expression is not valid
     */
    protected boolean matchesRole(FQAN regexpFQAN) throws ParseException {
        String regexpRole = regexpFQAN.getRole();
        if (regexpRole.contains(WILDCARD)) {
            // role contains a regular expression
            if (!regexpRole.equals(WILDCARD)) {
                throw new ParseException(
                        "Invalid regular expression within FQAN role, role is not '*'",
                        regexpFQAN.toString().indexOf(regexpRole));
            }
            return true;
        }

        // role doesn't contain a regular expression
        // since values are normalized
        return regexpRole.equals(role);
    }
}