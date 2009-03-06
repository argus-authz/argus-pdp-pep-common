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

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.Strings;

/** Status of an authorization request. */
@NotThreadSafe
public class Status implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -2716582237274156210L;

    /** Status message. */
    private String message;

    /** Code associated with the message. */
    private StatusCode statusCode;

    /** Constructor. */
    public Status() {
    }

    /**
     * Gets the message associated with this status.
     * 
     * @return message associated with this status
     */
    public String getMessage() {
        return message;
    }

    /**
     * Sets the message associated with this status.
     * 
     * @param newMessage message associated with this status
     */
    public void setMessage(String newMessage) {
        message = Strings.safeTrimOrNullString(newMessage);
    }

    /**
     * Gets the code for this status.
     * 
     * @return code for this status
     */
    public StatusCode getCode() {
        return statusCode;
    }

    /**
     * Sets the code for this status.
     * 
     * @param code code for this status
     */
    public void setCode(StatusCode code) {
        statusCode = code;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Status {");
        stringBuilder.append("statusCode: ").append(statusCode).append(", ");
        stringBuilder.append("message: ").append(message);
        stringBuilder.append("}");

        return stringBuilder.toString();
    }
}