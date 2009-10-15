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
import java.util.Set;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.LazySet;
import org.glite.authz.common.util.Strings;

/** Attribute-based description of the subject of an authorization request. */
@NotThreadSafe
public final class Subject implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 8938715874477342336L;

    /** Category to which the subject belongs. */
    private String category;

    /** Attributes describing the subject. */
    private LazySet<Attribute> attributes;

    /** Constructor. */
    public Subject() {
        attributes = new LazySet<Attribute>();
    }

    /**
     * Gets the category to which the subject belongs.
     * 
     * @return category to which the subject belongs
     */
    public String getCategory() {
        return category;
    }

    /**
     * Sets the category to which the subject belongs.
     * 
     * @param newCategory category to which the subject belongs
     */
    public void setCategory(String newCategory) {
        category = Strings.safeTrimOrNullString(newCategory);
    }

    /**
     * Gets the attributes that describe the subject.
     * 
     * @return attributes that describe the subject
     */
    public Set<Attribute> getAttributes() {
        return attributes;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Subject {");

        stringBuilder.append("category: ").append(category).append(", ");

        stringBuilder.append("attributes: [");
        for (Attribute attribute : attributes) {
            stringBuilder.append(attribute.toString()).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == category ? 0 : category.hashCode());
        hash = 31 * hash + attributes.hashCode();

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

        Subject otherSubject = (Subject) obj;
        return Strings.safeEquals(category, otherSubject.getCategory())
                && attributes.equals(otherSubject.getAttributes());
    }
}