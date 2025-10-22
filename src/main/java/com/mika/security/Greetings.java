package com.mika.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Greetings {

    @GetMapping("/hello-world")
    public String getMessage() {
        return "Hello World";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String getUserMessage() {
        return "Hello, User";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String getAdminMessage() {
        return "Hello, Admin";
    }
}
