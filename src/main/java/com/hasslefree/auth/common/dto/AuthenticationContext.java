package com.hasslefree.auth.common.dto;

import com.hasslefree.auth.common.enums.UserRole;

import java.util.Objects;
import java.util.Set;

/**
 * Represents the authentication context for a user across all services.
 * This contains all the essential information extracted from JWT tokens.
 */
public class AuthenticationContext {
    private String userId;
    private String username;
    private String email;
    private Set<UserRole> roles;
    private String accessToken;
    private Long tokenExpirationTime;

    // Constructors
    public AuthenticationContext() {}

    public AuthenticationContext(String userId, String username, String email, 
                               Set<UserRole> roles, String accessToken, Long tokenExpirationTime) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.roles = roles;
        this.accessToken = accessToken;
        this.tokenExpirationTime = tokenExpirationTime;
    }

    // Getters and Setters
    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<UserRole> getRoles() {
        return roles;
    }

    public void setRoles(Set<UserRole> roles) {
        this.roles = roles;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Long getTokenExpirationTime() {
        return tokenExpirationTime;
    }

    public void setTokenExpirationTime(Long tokenExpirationTime) {
        this.tokenExpirationTime = tokenExpirationTime;
    }

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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationContext that = (AuthenticationContext) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(username, that.username) &&
               Objects.equals(email, that.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, username, email);
    }

    @Override
    public String toString() {
        return "AuthenticationContext{" +
               "userId='" + userId + '\'' +
               ", username='" + username + '\'' +
               ", email='" + email + '\'' +
               ", roles=" + roles +
               ", tokenExpired=" + isTokenExpired() +
               '}';
    }
}
