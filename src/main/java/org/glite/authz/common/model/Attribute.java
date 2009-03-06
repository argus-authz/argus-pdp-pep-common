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

/** An attribute that identifies either a {@link Subject}, {@link Resource}, {@link Environment} or {@link Action}. */
@NotThreadSafe
public class Attribute implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = 3291370150790288490L;

    /** ID of the attribute. */
    private String id;

    /** Data type of the attribute. */
    private String dataType;

    /** Issuer of the attribute. */
    private String issuer;

    /** Values of the attribute. */
    private LazyList<Object> values;

    /** Constructor. */
    public Attribute() {
        values = new LazyList<Object>();
    }

    /**
     * Gets the ID of the attribute.
     * 
     * @return ID of the attribute
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the ID of the attribute.
     * 
     * @param newId ID of the attribute
     */
    public void setId(String newId) {
        id = Strings.safeTrimOrNullString(newId);
    }

    /**
     * Gets the data type of the attribute.
     * 
     * @return data type of the attribute
     */
    public String getDataType() {
        return dataType;
    }

    /**
     * Sets the data type of the attribute.
     * 
     * @param type data type of the attribute
     */
    public void setDataType(String type) {
        dataType = Strings.safeTrimOrNullString(type);
    }

    /**
     * Gets the issuer of the attribute.
     * 
     * @return issuer of the attribute
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the issuer of the attribute.
     * 
     * @param newIssuer issuer of the attribute
     */
    public void setIssuer(String newIssuer) {
        issuer = Strings.safeTrimOrNullString(newIssuer);
    }

    /**
     * Gets the values of the attribute.
     * 
     * @return values of the attribute
     */
    public List<Object> getValues() {
        return values;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("Attribute {");
        stringBuilder.append("id: ").append(id).append(", ");
        stringBuilder.append("dataType: ").append(dataType).append(", ");
        stringBuilder.append("issuer: ").append(issuer).append(", ");

        stringBuilder.append("values: [");
        for (Object value : values) {
            stringBuilder.append(value.toString()).append(", ");
        }
        stringBuilder.append("]");
        
        stringBuilder.append("}");

        return stringBuilder.toString();
    }
}