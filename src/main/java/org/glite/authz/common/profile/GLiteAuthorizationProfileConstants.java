/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * $Id$
 */

package org.glite.authz.common.profile;

/**
 * XACML namespaces, datatype and identifiers constants for the gLite <a
 * href="https://edms.cern.ch/document/1078881">XACML Grid Computing Element
 * Authorization Profile v1.0</a> and the <a
 * href="http://edms.cern.ch/document/1058175">XACML Grid Worker Node
 * Authorization Profile v1.0</a> profiles.
 */
public class GLiteAuthorizationProfileConstants {

    /** Namespaces, datatypes and identifiers name components separator */
    private static final char SEPARATOR= '/';

    /** The namespace base prefix {@value} */
    private static final String NS_PREFIX= "http://glite.org/xacml";

    /** The attribute namespace: {@value} . */
    public static final String NS_ATTRIBUTE= NS_PREFIX + SEPARATOR
            + "attribute";

    /** The action namespace: {@value} . */
    public static final String NS_ACTION= NS_PREFIX + SEPARATOR + "action";

    /** The datatype namespace: {@value} . */
    public static final String NS_DATATYPE= NS_PREFIX + SEPARATOR + "datatype";

    /** The profile namespace: {@value} . */
    public static final String NS_PROFILE= NS_PREFIX + SEPARATOR + "profile";

    /** The obligation namespace: {@value} . */
    public static final String NS_OBLIGATION= NS_PREFIX + SEPARATOR
            + "obligation";

    /** The algorithm namespace: {@value} . */
    public static final String NS_ALGORITHM= NS_PREFIX + SEPARATOR
            + "algorithm";

    /** The attribute id profile-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_PROFILE_ID= NS_ATTRIBUTE
            + SEPARATOR + "profile-id";

    /** The attribute id subject-issuer identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_ISSUER= NS_ATTRIBUTE
            + SEPARATOR + "subject-issuer";

    /** The attribute id x509-subject-issuer identifier: {@value} */
    public static final String ID_ATTRIBUTE_X509_SUBJECT_ISSUER = NS_ATTRIBUTE
        + SEPARATOR + "x509-subject-issuer";
    
    /** The attribute id x509-authn-profile identifier : {@value} */
    public static final String ID_ATTRIBUTE_X509_AUTHN_PROFILE = NS_ATTRIBUTE
        + SEPARATOR + "x509-authn-profile";
    
    /** The attribute id subject-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_ID= "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

    /** The attribute id subject key-info identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_KEY_INFO= "urn:oasis:names:tc:xacml:1.0:subject:key-info";

    /** The attribute id virtual-organization identifier: {@value} */
    public static final String ID_ATTRIBUTE_VIRTUAL_ORGANIZATION= NS_ATTRIBUTE
            + SEPARATOR + "virtual-organization";

    /** The attribute id FQAN identifier: {@value} */
    public static final String ID_ATTRIBUTE_FQAN= NS_ATTRIBUTE + SEPARATOR
            + "fqan";

    /** The attribute id primary FQAN identifier: {@value} */
    public static final String ID_ATTRIBUTE_PRIMARY_FQAN= ID_ATTRIBUTE_FQAN
            + SEPARATOR + "primary";

    /** The attribute id pilot-job-classifier identifier: {@value} */
    public static final String ID_ATTRIBUTE_PILOT_JOB_CLASSIFIER= NS_ATTRIBUTE
            + SEPARATOR + "pilot-job-classifier";

    /** The attribute id user-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_USER_ID= NS_ATTRIBUTE + SEPARATOR
            + "user-id";

    /** The attribute id group-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_GROUP_ID= NS_ATTRIBUTE + SEPARATOR
            + "group-id";

    /** The attribute id primary group-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_PRIMARY_GROUP_ID= ID_ATTRIBUTE_GROUP_ID
            + SEPARATOR + "primary";

    /** The attribute id resource-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_RESOURCE_ID= "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

    /** The attribute id action-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_ACTION_ID= "urn:oasis:names:tc:xacml:1.0:action:action-id";

    /** The obligation id map to local environment identifier: {@value} . */
    public static final String ID_OBLIGATION_LOCAL_ENV_MAP= NS_OBLIGATION
            + SEPARATOR + "local-environment-map";

    /** The obligation id map to POSIX environment identifier: {@value} . */
    public static final String ID_OBLIGATION_POSIX_ENV_MAP= ID_OBLIGATION_LOCAL_ENV_MAP
            + SEPARATOR + "posix";

    /** The datatype FQAN: {@value} */
    public static final String DATATYPE_FQAN= NS_DATATYPE + SEPARATOR + "fqan";

    /** The datatype #anyURI: {@value} */
    public static final String DATATYPE_ANY_URI= "http://www.w3.org/2001/XMLSchema#anyURI";

    /** The datatype #string: {@value} */
    public static final String DATATYPE_STRING= "http://www.w3.org/2001/XMLSchema#string";

    /** The datatype X.500 name (RFC2253 format DN): {@value} . */
    public static final String DATATYPE_X500_NAME= "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";

    /** The algorithm FQAN exact match id: {@value} */
    public static final String ID_ALGORITHM_FQAN_EXACT_MATCH= NS_ALGORITHM
            + SEPARATOR + "fqan-match";

    /** The algorithm FQAN regular expression match id: {@value} */
    public static final String ID_ALGORITHM_FQAN_REGEXP_MATCH= NS_ALGORITHM
            + SEPARATOR + "fqan-regexp-match";

    /**
     * Profile ID for the XACML Grid Worker Node Authorization Profile v1.0:
     * {@value}
     */
    public static final String GRID_WN_AUTHZ_V1_PROFILE_ID= NS_PROFILE
            + SEPARATOR + "grid-wn" + SEPARATOR + "1.0";

    /**
     * Profile ID for the XACML Grid Computing Element Authorization Profile
     * v1.0: {@value}
     */
    public static final String GRID_CE_AUTHZ_V1_PROFILE_ID= NS_PROFILE
            + SEPARATOR + "grid-ce" + SEPARATOR + "1.0";

}
