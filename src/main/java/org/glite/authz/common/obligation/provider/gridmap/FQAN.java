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

import org.glite.authz.common.util.Strings;

/** An FQAN (fully qualified attribute name. */
public class FQAN implements FullyQualifiedName {

    /** The group component of the FQAN. */
    private String group;

    /** The role component of the FQAN. */
    private String role;

    /**
     * Constructor.
     * 
     * @param name the FQAN
     */
    public FQAN(String name) {
        if (Strings.isEmpty(name)) {
            throw new IllegalArgumentException("FQAN may not be null or empty");
        }

        if (!name.contains("Role=")) {
            group = Strings.safeTrimOrNullString(name);
        } else {
            String[] components = name.split("/Role=");
            group = Strings.safeTrimOrNullString(components[0]);
            role = Strings.safeTrimOrNullString(components[1]);
        }

        if (group.charAt(group.length() - 1) == '/') {
            group = group.substring(0, group.length() - 1);
        }
    }

    /**
     * Gets the group component of the FQAN.
     * 
     * @return group component of the FQAN
     */
    public String getGroup() {
        return group;
    }

    /**
     * Gets the role component of the FQAN.
     * 
     * @return role component of the FQAN
     */
    public String getRole() {
        return role;
    }

    /** {@inheritDoc} */
    public String toString() {
        if (role == null) {
            return group;
        } else {
            return group + "/Role=" + role;
        }
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

        if (obj instanceof FQAN) {
            return hashCode() == obj.hashCode();
        }

        return false;
    }
}