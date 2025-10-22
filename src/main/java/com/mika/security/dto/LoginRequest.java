package com.mika.security.dto;

/**
 * DTO (Data Transfer Object) used to receive login credentials
 * from the client during authentication.
 */
public class LoginRequest {

    // Username or email used to log in
    private String username;

    // User's password
    private String password;

    public LoginRequest() {
    }

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
