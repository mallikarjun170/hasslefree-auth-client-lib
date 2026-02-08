package com.hasslefree.auth.common.constants;

/**
 * Constants for JWT claim names and authentication context. Centralizes string literals for better
 * maintainability and type safety.
 */
public final class ClaimConstants {

  private ClaimConstants() {
    throw new AssertionError("Cannot instantiate constants class");
  }

  // Standard JWT Claims
  public static final String CLAIM_SUBJECT = "sub";
  public static final String CLAIM_SUB = "sub"; // Alias for CLAIM_SUBJECT
  public static final String CLAIM_USERNAME = "username";
  public static final String CLAIM_COGNITO_USERNAME = "cognito:username";
  public static final String CLAIM_EMAIL = "email";
  public static final String CLAIM_EMAIL_VERIFIED = "email_verified";
  public static final String CLAIM_PHONE_NUMBER = "phone_number";
  public static final String CLAIM_PHONE_VERIFIED = "phone_number_verified";
  public static final String CLAIM_GIVEN_NAME = "given_name";
  public static final String CLAIM_FAMILY_NAME = "family_name";
  public static final String CLAIM_NAME = "name";
  public static final String CLAIM_PREFERRED_USERNAME = "preferred_username";
  public static final String CLAIM_EXP = "exp";

  // Custom Claims
  public static final String CLAIM_USER_ID = "custom:userId";
  public static final String CLAIM_CUSTOM_USER_ID = "custom:userId"; // Alias for CLAIM_USER_ID
  public static final String CLAIM_CUSTOM_ROLE = "custom:role";
  public static final String CLAIM_CUSTOM_ROLES = "custom:roles";
  public static final String CLAIM_ROLES = "roles";
  public static final String CLAIM_AUTHORITIES = "authorities";
  public static final String CLAIM_COGNITO_GROUPS = "cognito:groups";
  public static final String CLAIM_GROUPS = "groups";
  public static final String CLAIM_SCOPE = "scope";

  // Prefixes
  public static final String CLAIM_ROLE_PREFIX = "ROLE_";

  // Context Attribute Names
  public static final String AUTH_CONTEXT_ATTRIBUTE = "authContext";

  // Default Values
  public static final String DEFAULT_ROLE = "TENANT";

  // Token Masking
  public static final int TOKEN_MASKING_THRESHOLD = 10;
  public static final int TOKEN_MASKING_CHAR_COUNT = 3;
}
