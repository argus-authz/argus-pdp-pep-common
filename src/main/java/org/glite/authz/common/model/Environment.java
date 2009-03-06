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

/** An attribute-based description of the environment in which an {@link Action} is to be performed. */
@NotThreadSafe
public class Environment implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 4157470545855157618L;

    /** Attributes describing the environment. */
    private LazyList<Attribute> attributes;

    /** Constructor. */
    public Environment() {
        attributes = new LazyList<Attribute>();
    }

    /**
     * Gets the attributes that describe the environment.
     * 
     * @return attributes that describe the environment
     */
    public List<Attribute> getAttributes() {
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
}