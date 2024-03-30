package com.example.demo.dto;

import lombok.Data;

@Data
public class CustomUserInfoDto {
    private Long memberId;
    private String password;
    private String email;
    private String role;
}

