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

/** Description of an obligation that must be performed by the PEP. */
@NotThreadSafe
public final class Obligation implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -5500418892138258526L;

    /** ID for the obligation. */
    private String id;

    /** Which authorization decision activates this obligation. */
    private int fulfillOn;

    /** Any attribute assignments associated with the obligation. */
    private LazyList<AttributeAssignment> attributeAssignments;

    /** Constructor. */
    public Obligation() {
        attributeAssignments = new LazyList<AttributeAssignment>();
    }

    /**
     * Gets the ID of the obligation.
     * 
     * @return ID of the obligation
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the ID of the obligation.
     * 
     * @param newId ID of the obligation
     */
    public void setId(String newId) {
        id = Strings.safeTrimOrNullString(newId);
    }

    /**
     * Gets the authorization decision which activates this obligation.
     * 
     * @return authorization decision which activates this obligation
     */
    public int getFulfillOn() {
        return fulfillOn;
    }

    /**
     * Sets the authorization decision which activates this obligation. Permissible values are
     * {@link Result#DECISION_DENY} and {@link Result#DECISION_PERMIT}.
     * 
     * @param newFulfillOn authorization decision which activates this obligation
     */
    public void setFulfillOn(int newFulfillOn) {
        if (fulfillOn != Result.DECISION_DENY && fulfillOn != Result.DECISION_PERMIT) {
            throw new IllegalArgumentException("Invalid FulfillOn value");
        }
        fulfillOn = newFulfillOn;
    }

    /**
     * Gets the attribute assignments associated with this obligation.
     * 
     * @return attribute assignments associated with this obligation
     */
    public List<AttributeAssignment> getAttributeAssignments() {
        return attributeAssignments;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Obligation {");
        stringBuilder.append("id: ").append(id).append(", ");
        stringBuilder.append("fulfillOn: ").append(fulfillOn).append(", ");

        stringBuilder.append("attributeAssingments: [");
        for (AttributeAssignment assignment : attributeAssignments) {
            stringBuilder.append(assignment).append(", ");
        }
        stringBuilder.append("]");

        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == id ? 0 : id.hashCode());
        hash = 31 * hash + fulfillOn;
        hash = 31 * hash + attributeAssignments.hashCode();

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

        Obligation otherObligation = (Obligation) obj;
        return Strings.safeEquals(id, otherObligation.getId()) && fulfillOn == otherObligation.getFulfillOn()
                && attributeAssignments.equals(otherObligation.getAttributeAssignments());
    }
}