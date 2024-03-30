package com.example.demo.config;

import java.io.PrintWriter;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.example.demo.security.JwtAuthFilter;
import com.example.demo.security.JwtUtil;
import com.example.demo.service.CustomUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity // Spring Security 컨텍스트 설정임을 명시한다.
// @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //  Annotation을 통해서 Controller의 API들의 보안 수준을 설정할 수 있도록 활성화한다.
@AllArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;


    // PasswordEncoder는 BCryptPasswordEncoder를 사용
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    /**
     * 이 메서드는 정적 자원에 대해 보안을 적용하지 않도록 설정한다.
     * 정적 자원은 보통 HTML, CSS, JavaScript, 이미지 파일 등을 의미하며, 이들에 대해 보안을 적용하지 않음으로써 성능을 향상시킬 수 있다.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("X-Requested-With", "Content-Type", "Authorization", "X-XSRF-token"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .csrf(csrfConfig -> csrfConfig.disable()) // csrf 비활성화
            .cors(corsConfig -> corsConfig.configurationSource(corsConfigurationSource())) // cors 비활성화
//            .cors(Customizer.withDefaults())
            .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            //FormLogin, BasicHttp 비활성화
            .formLogin((form) -> form.disable())
            .httpBasic((httpBasic) -> httpBasic.disable())
            .headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable())); // X-Frame-Options 비활성화;

        // 권한 규칙 작성
        httpSecurity
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
//                        .requestMatchers(PathRequest.toH2Console()).permitAll()
						.requestMatchers("/", "/login", "/login/**", "/test", "/resources/**").permitAll()
//                        .requestMatchers("/posts/**", "/api/v1/posts/**").hasRole(RoleType.USER.name())
//                        .requestMatchers("/admins/**", "/api/v1/admins/**").hasRole(RoleType.ADMIN.name())
                        .anyRequest().authenticated()
            );

        //JwtAuthFilter를 UsernamePasswordAuthenticationFilter 앞에 추가
        httpSecurity.addFilterBefore(new JwtAuthFilter(customUserDetailsService, jwtUtil), UsernamePasswordAuthenticationFilter.class);

        httpSecurity.exceptionHandling((exceptionHandling) ->
                exceptionHandling.authenticationEntryPoint(unauthorizedEntryPoint)
                                .accessDeniedHandler(accessDeniedHandler)
            ); // 401 403 관련 예외처리;
        
        return httpSecurity.build();
    }

    // 인증이 안되었을때 처리할 부분(로그인 안한 사용자. jwt토큰 없을때, jwt토큰 유효기간 만료). 401 Unauthorized
    private final AuthenticationEntryPoint unauthorizedEntryPoint =
            (request, response, authException) -> {
                ErrorResponse fail = new ErrorResponse(HttpStatus.UNAUTHORIZED, "Spring security unauthorized...");
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                String json = new ObjectMapper().writeValueAsString(fail);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                PrintWriter writer = response.getWriter();
                writer.write(json);
                writer.flush();
            };

    // 권한이 없을때 처리할 부분(Role이 충분한 권한이 없는것). 403 Forbidden
    private final AccessDeniedHandler accessDeniedHandler =
            (request, response, accessDeniedException) -> {
                ErrorResponse fail = new ErrorResponse(HttpStatus.FORBIDDEN, "Spring security forbidden...");
                response.setStatus(HttpStatus.FORBIDDEN.value());
                String json = new ObjectMapper().writeValueAsString(fail);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                PrintWriter writer = response.getWriter();
                writer.write(json);
                writer.flush();
            };

    @Getter
    @RequiredArgsConstructor
    public class ErrorResponse {

        private final HttpStatus status;
        private final String message;
    }
}
