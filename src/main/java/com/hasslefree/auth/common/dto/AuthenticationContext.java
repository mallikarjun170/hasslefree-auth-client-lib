
package com.hasslefree.auth.common.dto;

import com.hasslefree.auth.common.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Represents the authentication context for a user across all services.
 * This contains all the essential information extracted from JWT tokens.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationContext {
    private String userId;
    private String username;
    private String email;
    private Set<UserRole> roles;
    private String accessToken;
    private Long tokenExpirationTime;

    // Utility methods
    public boolean hasRole(UserRole role) {
        return roles != null && roles.contains(role);
    }

    public boolean hasAnyRole(UserRole... roles) {
        if (this.roles == null || this.roles.isEmpty()) {
            return false;
        }
        for (UserRole role : roles) {
            if (this.roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasPrivilegeLevel(UserRole minimumRole) {
        if (roles == null || roles.isEmpty()) {
            return false;
        }
        return roles.stream().anyMatch(role -> role.hasPrivilegeLevel(minimumRole));
    }

    public boolean isTokenExpired() {
        return tokenExpirationTime != null && System.currentTimeMillis() > tokenExpirationTime;
    }

    @Override
    public String toString() {
        return "AuthenticationContext{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", roles=" + roles +
                ", accessToken='***MASKED***'" +
                ", tokenExpired=" + isTokenExpired() +
                '}';
    }
}
