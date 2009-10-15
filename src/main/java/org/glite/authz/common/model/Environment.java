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

/** An attribute-based description of the environment in which an {@link Action} is to be performed. */
@NotThreadSafe
public final class Environment implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 4988368497865461384L;

    /** Attributes describing the environment. */
    private LazySet<Attribute> attributes;

    /** Constructor. */
    public Environment() {
        attributes = new LazySet<Attribute>();
    }

    /**
     * Gets the attributes that describe the environment.
     * 
     * @return attributes that describe the environment
     */
    public Set<Attribute> getAttributes() {
        return attributes;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Environment {");

        stringBuilder.append("values: [");
        for (Attribute attribute : attributes) {
            stringBuilder.append(attribute).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return attributes.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        return attributes.equals(((Environment) obj).getAttributes());
    }
}