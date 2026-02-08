# Migration: Permission / Access-Grant Model (2026-02-08)

## Summary

This release standardizes authorization as access-grant/permission based.

## What changed

- Added immutable `AuthContext` as the primary auth model.
- Added canonical `Permission` and `AccessGrant` types.
- Added `Authorization` helper methods (`has`, `hasAny`, `hasAll`, `requireAny`, `requireAll`).
- Added `@RequireGrants` for declarative method protection.
- Removed legacy custom JWT validation/filter components from the library path.
- JWT signature validation remains the responsibility of Spring Security Resource Server.

## Service updates

1. Replace legacy auth context DTO usage with `AuthContext`.
2. Use `Authorization`/`@RequireGrants` for permission/access-grant checks.
3. Use `AuthorizationClient` and `hasslefree.auth.authorization-client.*` properties for remote checks.
4. Keep error-to-response mapping inside each service (prefer problem+json).
