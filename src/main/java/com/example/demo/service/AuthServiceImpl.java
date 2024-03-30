package com.example.demo.service;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.domain.Member;
import com.example.demo.dto.CustomUserInfoDto;
import com.example.demo.dto.LoginRequestDto;
import com.example.demo.repository.MemberRepository;
import com.example.demo.security.JwtUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService{

    private final JwtUtil jwtUtil;
    private final MemberRepository memberRepository;
    private final PasswordEncoder encoder;
//    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public String login(LoginRequestDto dto) {
        String email = dto.getEmail();
        String password = dto.getPassword();
        Member member = memberRepository.findMemberByEmail(email);
        if(member == null) {
            throw new UsernameNotFoundException("이메일이 존재하지 않습니다.");
        }

        // 암호화된 password를 디코딩한 값과 입력한 패스워드 값이 다르면 null 반환
		/*
		 * if(!encoder.matches(password, member.getPassword())) { throw new
		 * BadCredentialsException("비밀번호가 일치하지 않습니다."); }
		 */

        ModelMapper modelMapper = new ModelMapper();
        CustomUserInfoDto info = modelMapper.map(member, CustomUserInfoDto.class);

        String accessToken = jwtUtil.createAccessToken(info);
        return accessToken;
    }
}