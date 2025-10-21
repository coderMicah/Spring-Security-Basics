package com.mika.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Greetings {

    @GetMapping("/hello-world")
    public String getMessage() {
        return "Hello World";
    }
}
