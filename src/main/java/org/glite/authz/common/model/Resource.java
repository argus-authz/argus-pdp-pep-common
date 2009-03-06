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

/** An attribute-based description of the resource within which an {@link Action} to be authorized is made. */
@NotThreadSafe
public class Resource implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -8739476103285586961L;

    /** Content of the resource. */
    private String resourceContent;

    /** Attributes that describe the resource. */
    private LazyList<Attribute> attributes;

    /** Constructor. */
    public Resource() {
        attributes = new LazyList<Attribute>();
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
    public List<Attribute> getAttributes() {
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
}