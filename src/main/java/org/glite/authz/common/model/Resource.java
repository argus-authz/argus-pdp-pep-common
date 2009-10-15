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

/** An attribute-based description of the resource within which an {@link Action} to be authorized is made. */
@NotThreadSafe
public final class Resource implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -3526903430795707644L;

    /** Content of the resource. */
    private String resourceContent;

    /** Attributes that describe the resource. */
    private LazySet<Attribute> attributes;

    /** Constructor. */
    public Resource() {
        attributes = new LazySet<Attribute>();
    }

    /**
     * Gets the resource content.
     * 
     * @return resource content
     */
    public String getResourceContent() {
        return resourceContent;
    }

    /**
     * Sets the resource content.
     * 
     * @param content resource content
     */
    public void setResourceContent(String content) {
        resourceContent = Strings.safeTrimOrNullString(content);
    }

    /**
     * Gets the attributes that describe the resource.
     * 
     * @return attributes that describe the resource
     */
    public Set<Attribute> getAttributes() {
        return attributes;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Resource {");

        stringBuilder.append("resourceContent: ").append(resourceContent).append(", ");

        stringBuilder.append("attributes: [");
        for (Attribute attribute : attributes) {
            stringBuilder.append(attribute).append(", ");
        }
        stringBuilder.append("]");
        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == resourceContent ? 0 : resourceContent.hashCode());
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

        Resource otherResource = (Resource) obj;

        return Strings.safeEquals(resourceContent, otherResource.getResourceContent())
                && attributes.equals(otherResource.getAttributes());
    }
}