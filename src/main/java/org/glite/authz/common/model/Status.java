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

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.Strings;

/** Status of an authorization request. */
@NotThreadSafe
public final class Status implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -4406609342319994627L;

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

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == message ? 0 : message.hashCode());
        hash = 31 * hash + (null == statusCode ? 0 : statusCode.hashCode());

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

        Status otherStatus = (Status) obj;

        boolean codesEqual;
        if (statusCode == null) {
            if (otherStatus.getCode() == null) {
                codesEqual = true;
            } else {
                codesEqual = false;
            }
        } else {
            codesEqual = statusCode.equals(otherStatus.getCode());
        }

        return Strings.safeEquals(message, otherStatus.getMessage()) && codesEqual;
    }
}