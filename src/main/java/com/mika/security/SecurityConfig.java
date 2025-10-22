package com.mika.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
@EnableMethodSecurity
public class SecurityConfig {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

                http
                                // 🔒 Authorize requests — require authentication for any endpoint except
                                // h2-console
                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/h2-console/**").permitAll()
                                                .anyRequest().authenticated())

                                // 🧾 Enable default login form
                                .formLogin(withDefaults())

                                // 🔐 Enable HTTP Basic authentication (for tools like Postman)
                                .httpBasic(withDefaults())

                                // 🚫 Disable CSRF for simplicity (optional, depending on app type)
                                .csrf(csrf -> csrf.disable())

                                // Enable frame options to allow h2-console
                                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

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
