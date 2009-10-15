/*
 * Copyright 2008 Members of the EGEE Collaboration.
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

package org.glite.authz.common.model;

import java.io.Serializable;
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;

/** A requirement that a particular attribute have a given set of values within the PEP. */
@NotThreadSafe
public final class AttributeAssignment implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -1159499031052230298L;

    /** ID of the attribute. */
    private String attributeId;

    /** Values of the attribute. */
    private LazyList<String> values;

    /** Constructor. */
    public AttributeAssignment() {
        values = new LazyList<String>();
    }

    /**
     * Gets the ID of the attribute.
     * 
     * @return ID of the attribute
     */
    public String getAttributeId() {
        return attributeId;
    }

    /**
     * Sets the ID of the attribute.
     * 
     * @param id ID of the attribute
     */
    public void setAttributeId(String id) {
        attributeId = Strings.safeTrimOrNullString(id);
    }

    /**
     * Gets the values the identified attribute must be assigned.
     * 
     * @return values the identified attribute must be assigned
     */
    public List<String> getValues() {
        return values;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("AttributeAssignment {");
        stringBuilder.append("attributeId: ").append(attributeId).append(", ");

        stringBuilder.append("values: [");
        for (String value : values) {
            stringBuilder.append(value).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == attributeId ? 0 : attributeId.hashCode());
        hash = 31 * hash + values.hashCode();

        return hash;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        AttributeAssignment otherAssignment = (AttributeAssignment) obj;
        return Strings.safeEquals(attributeId, otherAssignment) && values.equals(otherAssignment.getValues());
    }
}