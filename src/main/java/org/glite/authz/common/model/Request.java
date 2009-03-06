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

/** An authorization request. */
@NotThreadSafe
public class Request implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 273060270038179896L;

    /** Subjects about which the request is being made. */
    private LazyList<Subject> subjects;

    /** Resources about which the request is being made. */
    private LazyList<Resource> resources;

    /** The action to be authorized. */
    private Action action;

    /** The environment within which the request is being made. */
    private Environment environment;

    /** Constructor. */
    public Request() {
        subjects = new LazyList<Subject>();
        resources = new LazyList<Resource>();
    }

    /**
     * Gets the subject about which the request is being made.
     * 
     * @return subject about which the request is being made
     */
    public List<Subject> getSubjects() {
        return subjects;
    }

    /**
     * Gets the resources about which the request is being made.
     * 
     * @return resources about which the request is being made
     */
    public List<Resource> getResources() {
        return resources;
    }

    /**
     * Gets the action about which the request is being made.
     * 
     * @return action about which the request is being made
     */
    public Action getAction() {
        return action;
    }

    /**
     * Sets the action about which the request is being made.
     * 
     * @param newAction action about which the request is being made
     */
    public void setAction(Action newAction) {
        action = newAction;
    }

    /**
     * Gets the environment about which the request is being made.
     * 
     * @return environment about which the request is being made
     */
    public Environment getEnvironment() {
        return environment;
    }

    /**
     * Sets the environment about which the request is being made.
     * 
     * @param newEnvironment environment about which the request is being made
     */
    public void setEnvironment(Environment newEnvironment) {
        environment = newEnvironment;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Request {");

        if (action != null) {
            stringBuilder.append("action: ").append(action).append(", ");
        }

        if (environment != null) {
            stringBuilder.append("environment: ").append(environment).append(", ");
        }

        stringBuilder.append("resources: [");
        for (Resource resource : resources) {
            stringBuilder.append(resource).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append(", ");

        stringBuilder.append("subjects: [");
        for (Subject subject : subjects) {
            stringBuilder.append(subject).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }
}