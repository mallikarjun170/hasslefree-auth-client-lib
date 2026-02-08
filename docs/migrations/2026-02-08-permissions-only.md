# 2026-02-08 Permissions-Only Authorization

## Summary
Roles are deprecated. Use permission checks via the authz client.

## Deprecations
- `UserRole` enum
- `AuthenticationContext.roles` and role helper methods
- `RoleAccessChecker`

## Migration Steps
1. Replace role-based checks with permission checks via `AuthzClient`.
2. Avoid relying on `AuthenticationContext.roles` for authorization decisions.
