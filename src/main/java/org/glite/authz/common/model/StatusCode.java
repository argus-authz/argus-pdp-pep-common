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

/** The code for a {@link Status}. */
@NotThreadSafe
public final class StatusCode implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 5112432894946515561L;

    /** The status code. */
    private String code;

    /** Subcode for this status. */
    private StatusCode subCode;

    /** Constructor. */
    public StatusCode() {
    }

    /**
     * Gets the code for this status.
     * 
     * @return code for this status
     */
    public String getCode() {
        return code;
    }

    /**
     * Sets the code for this status.
     * 
     * @param newCode code for this status
     */
    public void setCode(String newCode) {
        code = Strings.safeTrimOrNullString(newCode);
    }

    /**
     * Gets the subcode for this status.
     * 
     * @return subcode for this status
     */
    public StatusCode getSubCode() {
        return subCode;
    }

    /**
     * Sets the subcode for this status.
     * 
     * @param newSubCode subcode for this status
     */
    public void setSubCode(StatusCode newSubCode) {
        subCode = newSubCode;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("StatusCode {");
        stringBuilder.append("code: ").append(code).append(", ");
        stringBuilder.append("subCode: ").append(subCode);
        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == code ? 0 : code.hashCode());
        hash = 31 * hash + (null == subCode ? 0 : subCode.hashCode());

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

        StatusCode otherCode = (StatusCode) obj;

        boolean subCodesEqual;
        if (subCode == null) {
            if (otherCode.getSubCode() == null) {
                subCodesEqual = true;
            } else {
                subCodesEqual = false;
            }
        } else {
            subCodesEqual = subCode.equals(otherCode.getSubCode());
        }

        return Strings.safeEquals(code, otherCode.getCode()) && subCodesEqual;
    }
}