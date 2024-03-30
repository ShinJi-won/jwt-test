package com.example.demo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.LoginRequestDto;
import com.example.demo.service.AuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
//@RequestMapping("/api/v1/auth")
public class AuthApiController {

    private final AuthService authService;

    @PostMapping("/login")
//    public ResponseEntity<String> getMemberProfile(@Valid @RequestBody LoginRequestDto request) {
    public ResponseEntity<String> getMemberProfile(@RequestBody LoginRequestDto request) {
        String token = this.authService.login(request);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }
    
    @GetMapping("/test")
    public String test() {
    	return "test";
    }
    
    @GetMapping("/admin")
    public String admin() {
    	return "admin";
    }
}