package com.mika.security.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 🔐 AuthTokenFilter is a custom JWT filter that intercepts every HTTP request
 * once,
 * extracts the JWT from the request header, validates it, and sets the
 * authentication
 * in the Spring Security context if the token is valid.
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils; // Utility class for JWT operations (extracting, validating, parsing)

    @Autowired
    private UserDetailsService userDetailsService; // Loads user details (used to create Authentication object)

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /**
     * The core method executed once per request.
     * It checks for a JWT token in the Authorization header, validates it,
     * and sets the authentication for the user if the token is valid.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // Extract the JWT token from the request header
            String jwt = parseJwt(request);

            // Validate the JWT token
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                // Extract username (subject) from the token
                String username = jwtUtils.getUsernameFromJwtToken(jwt);

                // Load user details from the database (or another source)
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Create an authentication object using the user’s credentials and roles
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                // Add details such as IP address, session ID, etc.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication in the SecurityContext — marks the user as
                // authenticated
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            // Continue the filter chain (pass the request to the next filter)
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            // Log any error that occurs during token validation or authentication setup
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
    }

    /**
     * Extracts the JWT token from the HTTP request header.
     * Typically reads the "Authorization" header and removes the "Bearer " prefix.
     */
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java - Extracted JWT: {}", jwt);
        return jwt;
    }
}
