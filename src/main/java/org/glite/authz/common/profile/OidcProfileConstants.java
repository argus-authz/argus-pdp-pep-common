package org.glite.authz.common.profile;

public class OidcProfileConstants {

  protected static final char SEPARATOR = '/';

  protected static final String NS_PREFIX = "http://glite.org/xacml";

  public static final String NS_ATTRIBUTE = NS_PREFIX + SEPARATOR + "attribute";

  public static final String NS_ACTION = NS_PREFIX + SEPARATOR + "action";

  public static final String NS_PROFILE = NS_PREFIX + SEPARATOR + "profile";

  public static final String NS_OBLIGATION = NS_PREFIX + SEPARATOR
    + "obligation";

  public static final String ID_ATTRIBUTE_PROFILE_ID = NS_ATTRIBUTE + SEPARATOR
    + "profile-id";

  public static final String ID_ATTRIBUTE_OIDC_ACCESS_TOKEN = NS_ATTRIBUTE
    + SEPARATOR + "oidc-access-token";

  public static final String ID_ATTRIBUTE_OIDC_ORGANISATION = NS_ATTRIBUTE
    + SEPARATOR + "oidc-organisation";

  public static final String ID_ATTRIBUTE_OIDC_ISSUER = NS_ATTRIBUTE + SEPARATOR
    + "oidc-issuer";

  public static final String ID_ATTRIBUTE_OIDC_SUBJECT = NS_ATTRIBUTE
    + SEPARATOR + "oidc-subject";

  public static final String ID_ATTRIBUTE_OIDC_GROUPS = NS_ATTRIBUTE + SEPARATOR
    + "oidc-groups";

  public static final String ID_ATTRIBUTE_OIDC_USER_NAME = NS_ATTRIBUTE
    + SEPARATOR + "oidc-user-name";

  public static final String ID_ATTRIBUTE_OIDC_USER_ID = NS_ATTRIBUTE
    + SEPARATOR + "oidc-user-id";

  public static final String ID_ATTRIBUTE_OIDC_CLIENTID = NS_ATTRIBUTE
    + SEPARATOR + "oidc-client-id";

  public static final String ID_ATTRIBUTE_SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

  public static final String ID_ATTRIBUTE_RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

  public static final String ID_ATTRIBUTE_ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";

  /** The datatype #anyURI: {@value} */
  public static final String DATATYPE_ANY_URI = "http://www.w3.org/2001/XMLSchema#anyURI";

  /** The datatype #string: {@value} */
  public static final String DATATYPE_STRING = "http://www.w3.org/2001/XMLSchema#string";

  /** Common XACML Authorization Profile version: {@value} */
  public static final String OIDC_XACML_AUTHZ_V1_0_PROFILE_VERSION = "1.0";

  /** Common XACML Authorization Profile identifier: {@value} */
  public static final String OIDC_XACML_AUTHZ_V1_0_PROFILE_ID = NS_PROFILE
    + SEPARATOR + "oidc-authz" + SEPARATOR
    + OIDC_XACML_AUTHZ_V1_0_PROFILE_VERSION;

}
