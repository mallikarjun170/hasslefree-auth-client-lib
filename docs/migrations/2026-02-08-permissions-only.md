# 2026-02-08 Permissions-Only Authorization

## Summary
Role-based context has been removed. Use permission checks via the authz client.

## Removal
- `UserRole` enum
- `AuthenticationContext.roles` and role helper methods
- `RoleAccessChecker`

## Migration Steps
1. Replace role-based checks with permission checks via `AuthzClient`.
2. Avoid relying on any role claims for authorization decisions.
