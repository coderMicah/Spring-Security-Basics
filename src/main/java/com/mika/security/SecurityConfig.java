package com.mika.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
// 🧩 JdbcUserDetailsManager allows loading and saving users directly in a database
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

        @Autowired
        DataSource dataSource; // 💾 Inject the configured DataSource (connected to your DB)

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

                http
                                // 🔒 Secure all endpoints except the H2 console
                                .authorizeHttpRequests(authorize -> authorize
                                                .requestMatchers("/h2-console/**").permitAll()
                                                .anyRequest().authenticated())

                                // 🧾 Use Spring Security’s default login form
                                .formLogin(withDefaults())

                                // 🔐 Enable basic authentication (useful for Postman testing)
                                .httpBasic(withDefaults())

                                // ⚠️ Disable CSRF only for development/testing (not recommended in production)
                                .csrf(csrf -> csrf.disable())

                                // 🪟 Allow framing for H2 console
                                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

                return http.build();
        }

        @Bean
        public UserDetailsService userDetailsService() {

                // 👤 Step 1: Define a normal user
                UserDetails normalUser = User.withUsername("user")
                                .password(passwordEncoder().encode("user123"))
                                .roles("USER")
                                .build();

                // 👑 Step 2: Define an admin user
                UserDetails adminUser = User.withUsername("admin")
                                .password(passwordEncoder().encode("admin123"))
                                .roles("ADMIN")
                                .build();

                // ⚙️ Step 3: Previously, we used InMemoryUserDetailsManager to store users in
                // memory
                // return new InMemoryUserDetailsManager(normalUser, adminUser);

                // 💾 Step 4: Now we switch to JdbcUserDetailsManager to persist users in a
                // database
                JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

                // ✅ Step 5: Create (insert) the defined users into the DB if they don’t exist
                // yet
                // Note: JdbcUserDetailsManager expects tables like `users` and `authorities` in
                // your DB
                if (!jdbcUserDetailsManager.userExists("admin")) {
                        jdbcUserDetailsManager.createUser(adminUser);
                }
                if (!jdbcUserDetailsManager.userExists("user")) {
                        jdbcUserDetailsManager.createUser(normalUser);
                }

                // 🧩 Step 6: Return the JDBC-based user manager as the UserDetailsService
                return jdbcUserDetailsManager;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

}
