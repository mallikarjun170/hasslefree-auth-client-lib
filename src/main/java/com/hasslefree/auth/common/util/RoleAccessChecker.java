package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.enums.UserRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for role-based access control checks. Deprecated: HassleFree authorization is
 * permission-based via access_grants.
 */
@Deprecated
public class RoleAccessChecker {
  private static final Logger logger = LoggerFactory.getLogger(RoleAccessChecker.class);

  /**
   * Check if the user has the required role.
   *
   * @param context User authentication context
   * @param requiredRole The role required for access
   * @return true if user has the required role
   */
  public static boolean hasRole(AuthenticationContext context, UserRole requiredRole) {
    if (context == null || context.getRoles() == null) {
      logger.debug("Authentication context or roles are null");
      return false;
    }

    return context.hasRole(requiredRole);
  }

  /**
   * Check if the user has any of the specified roles.
   *
   * @param context User authentication context
   * @param roles Array of acceptable roles
   * @return true if user has at least one of the specified roles
   */
  public static boolean hasAnyRole(AuthenticationContext context, UserRole... roles) {
    if (context == null || context.getRoles() == null) {
      logger.debug("Authentication context or roles are null");
      return false;
    }

    return context.hasAnyRole(roles);
  }

  /**
   * Check if the user has the minimum privilege level required. Uses role hierarchy: ADMIN > OWNER
   * > MANAGER > TENANT
   *
   * @param context User authentication context
   * @param minimumRole The minimum role required
   * @return true if user has sufficient privilege level
   */
  public static boolean hasMinimumRole(AuthenticationContext context, UserRole minimumRole) {
    if (context == null || context.getRoles() == null) {
      logger.debug("Authentication context or roles are null");
      return false;
    }

    return context.hasPrivilegeLevel(minimumRole);
  }

  /**
   * Check if the user is an admin.
   *
   * @param context User authentication context
   * @return true if user has ADMIN role
   */
  public static boolean isAdmin(AuthenticationContext context) {
    return hasRole(context, UserRole.ADMIN);
  }

  /**
   * Check if the user is a property owner.
   *
   * @param context User authentication context
   * @return true if user has OWNER role
   */
  public static boolean isOwner(AuthenticationContext context) {
    return hasRole(context, UserRole.OWNER);
  }

  /**
   * Check if the user is a property manager.
   *
   * @param context User authentication context
   * @return true if user has MANAGER role
   */
  public static boolean isManager(AuthenticationContext context) {
    return hasRole(context, UserRole.MANAGER);
  }

  /**
   * Check if the user is a tenant.
   *
   * @param context User authentication context
   * @return true if user has TENANT role
   */
  public static boolean isTenant(AuthenticationContext context) {
    return hasRole(context, UserRole.TENANT);
  }

  /**
   * Check if the user can manage properties (ADMIN, OWNER, or MANAGER).
   *
   * @param context User authentication context
   * @return true if user can manage properties
   */
  public static boolean canManageProperties(AuthenticationContext context) {
    return hasAnyRole(context, UserRole.ADMIN, UserRole.OWNER, UserRole.MANAGER);
  }

  /**
   * Check if the user can access tenant features (all roles).
   *
   * @param context User authentication context
   * @return true if user can access tenant features
   */
  public static boolean canAccessTenantFeatures(AuthenticationContext context) {
    return hasAnyRole(context, UserRole.ADMIN, UserRole.OWNER, UserRole.MANAGER, UserRole.TENANT);
  }

  /**
   * Check if the user can perform administrative tasks (ADMIN only).
   *
   * @param context User authentication context
   * @return true if user can perform admin tasks
   */
  public static boolean canPerformAdminTasks(AuthenticationContext context) {
    return isAdmin(context);
  }

  /**
   * Check if the user is the same as the target user ID or has sufficient privileges. Used for
   * accessing user-specific resources.
   *
   * @param context User authentication context
   * @param targetUserId The user ID being accessed
   * @param minimumRoleOverride Minimum role that can override user ID check
   * @return true if user can access the target user's resources
   */
  public static boolean canAccessUserResources(
      AuthenticationContext context, String targetUserId, UserRole minimumRoleOverride) {
    if (context == null || context.getUserId() == null) {
      logger.debug("Authentication context or user ID is null");
      return false;
    }

    // User can access their own resources
    if (context.getUserId().equals(targetUserId)) {
      return true;
    }

    // Or if they have sufficient privileges
    return hasMinimumRole(context, minimumRoleOverride);
  }

  /**
   * Check if the user can access user resources with MANAGER level override.
   *
   * @param context User authentication context
   * @param targetUserId The user ID being accessed
   * @return true if user can access the target user's resources
   */
  public static boolean canAccessUserResourcesAsManager(
      AuthenticationContext context, String targetUserId) {
    return canAccessUserResources(context, targetUserId, UserRole.MANAGER);
  }

  /**
   * Check if the user can access user resources with OWNER level override.
   *
   * @param context User authentication context
   * @param targetUserId The user ID being accessed
   * @return true if user can access the target user's resources
   */
  public static boolean canAccessUserResourcesAsOwner(
      AuthenticationContext context, String targetUserId) {
    return canAccessUserResources(context, targetUserId, UserRole.OWNER);
  }

  /**
   * Check if the authentication context is valid and not expired.
   *
   * @param context User authentication context
   * @return true if context is valid and token is not expired
   */
  public static boolean isValidContext(AuthenticationContext context) {
    if (context == null) {
      logger.debug("Authentication context is null");
      return false;
    }

    if (context.getUserId() == null || context.getUserId().trim().isEmpty()) {
      logger.debug("User ID is null or empty");
      return false;
    }

    if (context.isTokenExpired()) {
      logger.debug("Token is expired for user: {}", context.getUserId());
      return false;
    }

    return true;
  }

  /**
   * Log access decision for debugging and auditing purposes.
   *
   * @param context User authentication context
   * @param resource The resource being accessed
   * @param action The action being performed
   * @param allowed Whether access was allowed
   */
  public static void logAccessDecision(
      AuthenticationContext context, String resource, String action, boolean allowed) {
    if (context != null) {
      logger.info(
          "Access {} for user {} ({}) to {} resource '{}' - Roles: {}",
          allowed ? "GRANTED" : "DENIED",
          context.getUsername(),
          context.getUserId(),
          action,
          resource,
          context.getRoles());
    } else {
      logger.warn("Access DENIED for null context to {} resource '{}'", action, resource);
    }
  }
}
