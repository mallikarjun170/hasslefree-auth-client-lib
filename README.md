

# Hasslefree Auth Client Library

`auth-client-lib` is a robust, production-grade Java library for authentication and authorization, designed for seamless integration with AWS Cognito and JWT-based systems. It provides utilities for token validation, context extraction, and role-based access control, with a focus on security, testability, and code quality.

## Features

- **JWT Token Validation**: Securely validates and parses JWTs, including AWS Cognito tokens, with signature, expiration, issuer, and audience checks.
- **Custom Exception Handling**: Throws meaningful exceptions (`InvalidTokenException`, `TokenExpiredException`) for all error cases.
- **Role-Based Access Checks**: Utilities for enforcing fine-grained access control based on user roles.
- **Context Extraction**: Extracts user and role information from tokens for downstream use.
- **Defensive Coding**: Handles null, empty, and malformed tokens gracefully.
- **Comprehensive Javadoc**: All public APIs are fully documented.
- **Code Quality & Coverage**: CI runs Checkstyle, SpotBugs, and JaCoCo coverage on every push/PR.

## Getting Started

### Add as a Dependency

Add to your Maven `pom.xml`:

```xml
<dependency>
	<groupId>com.hasslefree</groupId>
	<artifactId>auth-client-lib</artifactId>
	<version>1.0-SNAPSHOT</version>
</dependency>
```

### Example Usage

```java
JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "yourUserPoolId", "https://cognito-idp.us-east-1.amazonaws.com/yourUserPoolId/.well-known/jwks.json");
try {
		boolean valid = validator.validateToken(token);
		String username = validator.getUsernameFromToken(token);
		String userId = validator.getUserIdFromToken(token);
		// ...
} catch (InvalidTokenException | TokenExpiredException e) {
		// Handle invalid/expired token
}
```

See Javadoc for full API details and advanced usage.

## Development & Testing

- **Run all checks:**
	```sh
	mvn clean verify
	```
- **Run tests only:**
	```sh
	mvn test
	```
- **Code coverage report:**
	Output at `target/site/jacoco/index.html` after running tests.

## Continuous Integration

Every push and pull request triggers GitHub Actions to:
- Build and test the library
- Run code coverage (JaCoCo)
- Enforce code style (Checkstyle)
- Run static analysis (SpotBugs)
- Upload coverage to Codecov

See `.github/workflows/ci.yml` for details.

## Security Notes

- Always validate JWTs from trusted sources only
- Use HTTPS for all network communication
- Never log sensitive token data

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and notable changes.

## Contributing

Contributions are welcome! Please see `CONTRIBUTING.md` for guidelines, or open an issue/PR.

## License

This project is licensed under the MIT License.
