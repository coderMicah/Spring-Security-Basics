package com.mika.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // 🔒 Authorize all requests — require authentication for any endpoint
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())

                // 🧾 Enable default login form
                .formLogin(withDefaults())

                // 🔐 Enable HTTP Basic authentication (for tools like Postman)
                .httpBasic(withDefaults())

                // 🚫 Disable CSRF for simplicity (optional, depending on app type)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // 👤 Normal User
        UserDetails normalUser = User.withUsername("user")
                .password("{noop}user123") // {noop} means no password encoder
                .roles("USER")
                .build();

        // 👑 Admin User
        UserDetails adminUser = User.withUsername("admin")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build();

        // ✅ Register both users in memory
        return new InMemoryUserDetailsManager(normalUser, adminUser);
    }

}
