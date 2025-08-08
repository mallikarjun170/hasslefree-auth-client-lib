
# HassleFree Auth Client Library

Production-ready Java library for extracting authentication context from JWT tokens in microservices.

## Features
- Extracts user ID, username, email, roles, and expiration from JWTs
- Supports multiple role claim formats (Cognito, custom, etc.)
- Secure: No secrets in logs, tokens masked, signature/algorithm validation stub
- Performance: Null checks, efficient role extraction, thread-safe
- Fully unit tested

## Usage
Add as a dependency in your Maven project:
```xml
<dependency>
	<groupId>com.hasslefree.auth</groupId>
	<artifactId>auth-client-lib</artifactId>
	<version>1.0.0</version>
</dependency>
```

Extract context from a JWT token:
```java
AuthenticationContext ctx = AuthContextExtractor.extractFromToken(token);
```

## Security Notes
- Always validate JWT signature and algorithm (see TODO in code for public key validation)
- Never log full tokens or secrets
- Use the provided utility methods for safe extraction

## Contributing
Pull requests are welcome! Please add tests for new features and follow the existing code style.

## License
MIT
