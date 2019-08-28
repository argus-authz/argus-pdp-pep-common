/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * $Id$
 */
package org.glite.authz.common.profile;

public class OidcProfileConstants {

  protected static final char SEPARATOR = '/';

  protected static final String NS_PREFIX = "http://glite.org/xacml";

  public static final String NS_ATTRIBUTE = NS_PREFIX + SEPARATOR + "attribute";

  public static final String NS_ACTION = NS_PREFIX + SEPARATOR + "action";

  public static final String NS_PROFILE = NS_PREFIX + SEPARATOR + "profile";

  public static final String NS_OBLIGATION = NS_PREFIX + SEPARATOR + "obligation";

  public static final String ID_ATTRIBUTE_PROFILE_ID = NS_ATTRIBUTE + SEPARATOR + "profile-id";

  public static final String ID_ATTRIBUTE_OIDC_ACCESS_TOKEN =
      NS_ATTRIBUTE + SEPARATOR + "oidc-access-token";

  public static final String ID_ATTRIBUTE_OIDC_ORGANISATION =
      NS_ATTRIBUTE + SEPARATOR + "oidc-organisation";

  public static final String ID_ATTRIBUTE_OIDC_ISSUER = NS_ATTRIBUTE + SEPARATOR + "oidc-issuer";

  public static final String ID_ATTRIBUTE_OIDC_SUBJECT = NS_ATTRIBUTE + SEPARATOR + "oidc-subject";

  public static final String ID_ATTRIBUTE_OIDC_GROUP = NS_ATTRIBUTE + SEPARATOR + "oidc-group";

  public static final String ID_ATTRIBUTE_OIDC_SCOPE = NS_ATTRIBUTE + SEPARATOR + "oidc-scope";

  public static final String ID_ATTRIBUTE_OIDC_USER_NAME =
      NS_ATTRIBUTE + SEPARATOR + "oidc-user-name";

  public static final String ID_ATTRIBUTE_OIDC_USER_ID = NS_ATTRIBUTE + SEPARATOR + "oidc-user-id";

  public static final String ID_ATTRIBUTE_OIDC_CLIENTID =
      NS_ATTRIBUTE + SEPARATOR + "oidc-client-id";

  public static final String ID_ATTRIBUTE_SUBJECT_ID =
      "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

  public static final String ID_ATTRIBUTE_RESOURCE_ID =
      "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

  public static final String ID_ATTRIBUTE_ACTION_ID =
      "urn:oasis:names:tc:xacml:1.0:action:action-id";

  /** The datatype #anyURI: {@value} */
  public static final String DATATYPE_ANY_URI = "http://www.w3.org/2001/XMLSchema#anyURI";

  /** The datatype #string: {@value} */
  public static final String DATATYPE_STRING = "http://www.w3.org/2001/XMLSchema#string";

  /** Common XACML Authorization Profile version: {@value} */
  public static final String OIDC_XACML_AUTHZ_V1_0_PROFILE_VERSION = "1.0";

  /** Common XACML Authorization Profile identifier: {@value} */
  public static final String OIDC_XACML_AUTHZ_V1_0_PROFILE_ID =
      NS_PROFILE + SEPARATOR + "oidc-authz" + SEPARATOR + OIDC_XACML_AUTHZ_V1_0_PROFILE_VERSION;

}
