package com.example.security1.config;

import com.example.security1.config.oauth.*;
import com.example.security1.config.oauth.provider.JwtUtils;
import com.example.security1.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Collections;
import java.util.List;


@Configuration
@EnableWebSecurity  //스프링 시큐리티 필터가 스프링 필터체인에 등록됨 (시큐리티가 기본 제공하는 필터를 재정의, 덮어씌움)
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)    //secured, pre/postAuthorize 어노테이션 활성화
public class SecurityConfig{

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    //@Autowired
    //private CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //csrf -> csrf 공격에 대한 옵션
        //authorizeHttpRequests -> 페이지 접근 권한 설정
        //formLogin -> 권한이 필요한 요청이 리다이렉트할 URL 설정
        //oauth2Login -> oauth 라이브러리 인증기능 설정
        return http
                .csrf(cs-> cs.disable())
                //.addFilter(corsFilter)
                .cors(cors -> cors.configurationSource(new CorsConfigurationSource(){
                        @Override
                        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                            CorsConfiguration configuration = new CorsConfiguration();

                            configuration.setAllowedOrigins(List.of("http://localhost:55846/"));
                            configuration.setAllowedMethods(List.of("*"));
                            configuration.setAllowCredentials(true);
                            configuration.setAllowedHeaders(List.of("*"));

                            configuration.setExposedHeaders(List.of("*"));
                            return configuration;
                        }
                }))

                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .requestMatchers("/user").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()).
                formLogin((formLogin) -> {
                    formLogin.loginPage("/loginForm") //.usernameParameter("something") //username 외의 별개의 파라미터 사용을 원하면 사용
                            .loginProcessingUrl("/login") //login 주소가 호출되면 시큐리티가 낚아채서 대신 진행해줌
                            .defaultSuccessUrl("/");    //로그인이 정상진행 됐을 떄 (PricncipalDetailService) 처음 요청페이지로 리다이렉트 (파라미터는 추가 경로)
                })
                .oauth2Login(oauth2Login -> oauth2Login.loginPage("/loginForm")//oauth 인증을 위한 로그인 페이지로 넘어갈 base 주소 설정
                        .successHandler(new MyAuthenticationSuccessHandler(jwtUtils))
                        .failureHandler(new MyAuthenticationFailureHandler())
                        .userInfoEndpoint(endpoint ->
                                endpoint.userService(principalOauth2UserService)))  //oauth 로그인 이후 진행할 로직 설정
                .addFilterBefore(new JwtAuthorizationFilter(userRepository, jwtUtils),OAuth2LoginAuthenticationFilter.class)
                .build();
                //구글의 경우 로그인 후 엑세스 토큰 + 사용자 프로필 정보를 받음

    }
}
