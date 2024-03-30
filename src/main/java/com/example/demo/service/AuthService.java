package com.example.demo.service;

import com.example.demo.dto.LoginRequestDto;

public interface AuthService {
    String login(LoginRequestDto request);

}
