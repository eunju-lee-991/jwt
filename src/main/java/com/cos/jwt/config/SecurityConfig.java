package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CorsFilter corsFilter) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)// session 사용 안함
                .and()
                .addFilter(corsFilter) // 인증이 필요할 때 시큐리티 필터에 등록...? @CrossOrigin 쓰면 인증이 필요없는 요청만 처리해서?
                .formLogin().disable() // jwt 쓰면 폼 로그인 안함?
                .httpBasic().disable() // 다른 도메인에서 요청할 때 httponly라서 cookie 못 보낼 때 Authorization: ID, PW 헤더 보내는 방식이 httpBasic
                                        // 우리가 하려는 건 Authorization: 토큰 을 보내는 것 -> Bearer
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

        return http.build();
    }

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true); //내 서버가 응답할 때 JSON을 자바스크립트에서 처리할 수 있게 할지 설정
        configuration.addAllowedHeader("*"); // 모든 ip에 응답 허용
        configuration.addAllowedOrigin("*"); // 모든 헤더 //
        configuration.addAllowedMethod("*");
        source.registerCorsConfiguration("/api/**", configuration); // 저 url 패턴으로 들어오는 요청은 configuration 설정

        return new CorsFilter(source);
    }

}
