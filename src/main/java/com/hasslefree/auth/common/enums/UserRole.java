package com.hasslefree.auth.common.enums;

/**
 * Enumeration for user roles across the system. These roles are used consistently across all
 * microservices.
 */
/** Deprecated: Roles are no longer used for authorization. Retained for backward compatibility. */
@Deprecated
public enum UserRole {
  TENANT("ROLE_TENANT", "Regular tenant user with access to booking and rental features"),
  OWNER("ROLE_OWNER", "Property owner with management capabilities"),
  MANAGER("ROLE_MANAGER", "Property manager with operational access"),
  ADMIN("ROLE_ADMIN", "System administrator with full access");

  private final String authority;
  private final String description;

  UserRole(String authority, String description) {
    this.authority = authority;
    this.description = description;
  }

  public String getAuthority() {
    return authority;
  }

  public String getDescription() {
    return description;
  }

  /**
   * Check if this role has higher or equal privilege than the given role. Hierarchy: ADMIN > OWNER
   * > MANAGER > TENANT
   */
  public boolean hasPrivilegeLevel(UserRole role) {
    return this.ordinal() >= role.ordinal();
  }

  /** Get role from authority string (e.g., "ROLE_ADMIN" -> UserRole.ADMIN) */
  public static UserRole fromAuthority(String authority) {
    for (UserRole role : values()) {
      if (role.authority.equals(authority)) {
        return role;
      }
    }
    throw new IllegalArgumentException("Unknown authority: " + authority);
  }

  /** Get role from string name (case insensitive) */
  public static UserRole fromString(String roleName) {
    try {
      return UserRole.valueOf(roleName.toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Unknown role: " + roleName);
    }
  }
}
