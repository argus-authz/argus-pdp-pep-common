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

package org.glite.authz.common.model;

import java.io.Serializable;
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;

/** Attribute-based description of the subject of an authorization request. */
@NotThreadSafe
public class Subject implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -240320117226294650L;

    /** Category to which the subject belongs. */
    private String category;

    /** Attributes describing the subject. */
    private LazyList<Attribute> attributes;

    /** Constructor. */
    public Subject() {
        attributes = new LazyList<Attribute>();
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
    public List<Attribute> getAttributes() {
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
}