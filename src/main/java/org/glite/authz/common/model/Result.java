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
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;

/** Result of an authorization request. */
@NotThreadSafe
public final class Result implements Serializable {

    /** Decision Deny value, {@value} . */
    public static final int DECISION_DENY = 0;

    /** Decision Permit value, {@value} . */
    public static final int DECISION_PERMIT = 1;

    /** Decision Indeterminate value, {@value} . */
    public static final int DECISION_INDETERMINATE = 2;

    /** Decision NotApplicable value, {@value} . */
    public static final int DECISION_NOT_APPLICABLE = 3;

    /** Serial version UID. */
    private static final long serialVersionUID = 6419281476715041885L;

    /** Decision of the authorization request. */
    private int decision;

    /** ID of the resource to which the result corresponds. */
    private String resourceId;

    /** Status message associated with the result. */
    private Status status;

    /** Obligations associated with the result. */
    private LazyList<Obligation> obligations;

    /** Constructor. */
    public Result() {
        obligations = new LazyList<Obligation>();
    }

    /**
     * Gets the decision of the authorization request.
     * 
     * @return decision of the authorization request
     */
    public int getDecision() {
        return decision;
    }

    /**
     * Helper method for converting the numeric decision code to its equivalent XACML string.
     * 
     * @return numeric decision code's equivalent XACML string
     */
    public String getDecisionString() {
        switch (decision) {
            case 0:
                return "Deny";
            case 1:
                return "Permit";
            case 2:
                return "Indeterminate";
            case 3:
                return "NotApplicable";
            default:
                return null;
        }
    }

    /**
     * Sets the decision of the authorization request.
     * 
     * @param newDecision decision of the authorization request
     */
    public void setDecision(int newDecision) {
        if (decision != DECISION_DENY && decision != DECISION_PERMIT && decision != DECISION_INDETERMINATE
                && decision != DECISION_NOT_APPLICABLE) {
            throw new IllegalArgumentException("Invalid decision value");
        }
        decision = newDecision;
    }

    /**
     * Gets the ID of the resource to which the result applies.
     * 
     * @return ID of the resource to which the result applies
     */
    public String getResourceId() {
        return resourceId;
    }

    /**
     * Sets the ID of the resource to which the result applies.
     * 
     * @param id ID of the resource to which the result applies
     */
    public void setResourceId(String id) {
        resourceId = Strings.safeTrimOrNullString(id);
    }

    /**
     * Gets the status message associated with the result.
     * 
     * @return status message associated with the result
     */
    public Status getStatus() {
        return status;
    }

    /**
     * Sets the status message associated with the result.
     * 
     * @param newStatus status message associated with the result
     */
    public void setStatus(Status newStatus) {
        status = newStatus;
    }

    /**
     * Gets the obligations associated with this result.
     * 
     * @return obligations associated with this result
     */
    public List<Obligation> getObligations() {
        return obligations;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Result {");

        stringBuilder.append("decision: ").append(decision).append(", ");
        stringBuilder.append("resourceId: ").append(resourceId).append(", ");
        stringBuilder.append("status: ").append(status).append(", ");

        stringBuilder.append("obligations: [");
        for (Obligation obligation : obligations) {
            stringBuilder.append(obligation).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + decision;
        hash = 31 * hash + (null == resourceId ? 0 : resourceId.hashCode());
        hash = 31 * hash + obligations.hashCode();
        hash = 31 * hash + (null == status ? 0 : status.hashCode());

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

        Result otherResult = (Result) obj;

        boolean statsEqual;
        if (status == null) {
            if (otherResult.getStatus() == null) {
                statsEqual = true;
            } else {
                statsEqual = false;
            }
        } else {
            statsEqual = status.equals(otherResult.getStatus());
        }

        return decision == otherResult.getDecision() && Strings.safeEquals(resourceId, otherResult.getResourceId())
                && obligations.equals(otherResult.getObligations()) && statsEqual;
    }
}