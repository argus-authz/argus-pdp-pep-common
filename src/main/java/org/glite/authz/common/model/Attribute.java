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
import org.glite.authz.common.util.Strings;

/**
 * An attribute that identifies either a {@link Subject}, {@link Resource}, {@link Environment} or {@link Action}.
 * 
 * If no data type is given for an attribute the data type defaults to {@value #DT_STRING}.
 */
@NotThreadSafe
public final class Attribute implements Serializable {

    /** The string data type URI, {@value} . */
    public static final String DT_STRING = "http://www.w3.org/2001/XMLSchema#string";

    /** The boolean data type URI, {@value} . */
    public static final String DT_BOOLEAN = "http://www.w3.org/2001/XMLSchema#boolean";

    /** The integer data type URI, {@value} . */
    public static final String DT_INTEGER = "http://www.w3.org/2001/XMLSchema#integer";

    /** The double data type URI, {@value} . */
    public static final String DT_DOUBLE = "http://www.w3.org/2001/XMLSchema#double";

    /** The time data type URI, {@value} . */
    public static final String DT_TIME = "http://www.w3.org/2001/XMLSchema#time";

    /** The date data type URI, {@value} . */
    public static final String DT_DATE = "http://www.w3.org/2001/XMLSchema#date";

    /** The date/time data type URI, {@value} . */
    public static final String DT_DATE_TIME = "http://www.w3.org/2001/XMLSchema#dateTime";

    /** The XQuery dayTimeDuration data type URI, {@value} . */
    public static final String DT_DAY_TIME = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#dayTimeDuration";

    /** The XQuery yearMonthDuration data type URI, {@value} . */
    public static final String DT_YEAR_MONTH = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#yearMonthDuration";

    /** The any URI data type URI, {@value} . */
    public static final String DT_ANY_URI = "http://www.w3.org/2001/XMLSchema#anyURI";

    /** The hex-encoded binary data type URI, {@value} . */
    public static final String DT_HEX_BINARY = "http://www.w3.org/2001/XMLSchema#hexBinary";

    /** The base64-encoded binary data type URI, {@value} . */
    public static final String DT_BASE64_BINARY = "http://www.w3.org/2001/XMLSchema#base64Binary";

    /** The RFC822 name (email address) data type URI, {@value} . */
    public static final String DT_RFC822_NAME = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";

    /** The X.500 name (DN) data type URI, {@value} . */
    public static final String DT_X500_NAME = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";

    /** The action ID attribute ID, {@value} . */
    public static final String ID_ACT_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";

    /** The action implied action attribute ID, {@value} . */
    public static final String ID_ACT_IMPLIED_ACTION = "urn:oasis:names:tc:xacml:1.0:action:implied-action";

    /** The environment current time attribute ID, {@value} . */
    public static final String ID_ENV_CURRENT_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";

    /** The environment current date attribute ID, {@value} . */
    public static final String ID_ENV_CURRENT_DATE = "urn:oasis:names:tc:xacml:1.0:environment:current-date";

    /** The environment current date/time attribute ID, {@value} . */
    public static final String ID_ENV_CURRENT_DATE_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

    /** The resource location attribute ID, {@value} . */
    public static final String ID_RES_LOCATION = "urn:oasis:names:tc:xacml:1.0:resource:resource-location";

    /** The resource ID attribute ID, {@value} . */
    public static final String ID_RES_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

    /** The resource simple file name attribute ID, {@value} . */
    public static final String ID_RES_SIMPLE_FILE_NAME = "urn:oasis:names:tc:xacml:1.0:resource:simple-file-name";

    /** The subject authentication locality DNS name attribute ID, {@value} . */
    public static final String ID_SUB_AUTHN_DNS_NAME = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:dns-name";

    /** The subject authentication locality IP address attribute ID, {@value} . */
    public static final String ID_SUB_AUTHN_IP_ADDRESS = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:ip-address";

    /** The subject authentication method attribute ID, {@value} . */
    public static final String ID_SUB_AUTHN_METHOD = "urn:oasis:names:tc:xacml:1.0:subject:authentication-method";

    /** The subject authentication time attribute ID, {@value} . */
    public static final String ID_SUB_AUTHN_TIME = "urn:oasis:names:tc:xacml:1.0:subject:authentication-time";

    /** The subject key information attribute ID, {@value} . */
    public static final String ID_SUB_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info";

    /** The subject request time attribute ID, {@value} . */
    public static final String ID_SUB_REQUEST_TIME = "urn:oasis:names:tc:xacml:1.0:subject:request-time";

    /** The subject session start time attribute ID, {@value} . */
    public static final String ID_SUB_SESSION_START_TIME = "urn:oasis:names:tc:xacml:1.0:subject:session-start-time";

    /** The subject ID attribute ID, {@value} . */
    public static final String ID_SUB_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

    /** The subject ID qualifier attribute ID, {@value} . */
    public static final String ID_SUB_ID_QUALIFIER = "urn:oasis:names:tc:xacml:1.0:subject:subject-id-qualifier";

    /** The subject category access subject attribute ID, {@value} . */
    public static final String ID_SUB_CAT_ACCESS_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";

    /** The subject category codebase attribute ID, {@value} . */
    public static final String ID_SUB_CAT_CODEBASE = "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";

    /** The subject category intermediary subject attribute ID, {@value} . */
    public static final String ID_SUB_CAT_INTERMEDIARY_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";

    /** The subject category recipient attribute ID, {@value} . */
    public static final String ID_SUB_CAT_RECIPIENT_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";

    /** The subject category requesting machine attribute ID, {@value} . */
    public static final String ID_SUB_CAT_REQUEST_MACHINE = "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";

    /** Serial version UID. */
    private static final long serialVersionUID = -998357326993743203L;

    /** ID of the attribute. */
    private String id;

    /** Data type of the attribute. */
    private String dataType;

    /** Issuer of the attribute. */
    private String issuer;

    /** Values of the attribute. */
    private LazySet<Object> values;

    /** Constructor. */
    public Attribute() {
        dataType = DT_STRING;
        values = new LazySet<Object>();
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
    public Set<Object> getValues() {
        return values;
    }

    /** {@inheritDoc}. */
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

    /** {@inheritDoc}. */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == id ? 0 : id.hashCode());
        hash = 31 * hash + (null == dataType ? 0 : dataType.hashCode());
        hash = 31 * hash + (null == issuer ? 0 : issuer.hashCode());
        hash = 31 * hash + values.hashCode();

        return hash;
    }

    /** {@inheritDoc}. */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        Attribute otherAttribute = (Attribute) obj;
        return Strings.safeEquals(id, otherAttribute.getId())
                && Strings.safeEquals(dataType, otherAttribute.getDataType())
                && Strings.safeEquals(issuer, otherAttribute.getIssuer()) && values.equals(otherAttribute.getValues());
    }
}