package com.mika.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
}
