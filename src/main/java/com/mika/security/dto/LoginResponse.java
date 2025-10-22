package com.mika.security.dto;

import java.util.List;

/**
 * DTO used to send authentication response data
 * back to the client after a successful login.
 */
public class LoginResponse {

    // Username of the authenticated user
    private String username;

    // Roles or authorities assigned to the user
    private List<String> roles;

    // JWT token generated upon successful login
    private String token;

    public LoginResponse() {
    }

    // Constructor used by your controller
    public LoginResponse(String username, List<String> roles, String token) {
        this.username = username;
        this.roles = roles;
        this.token = token;
    }

    // Getters and setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
