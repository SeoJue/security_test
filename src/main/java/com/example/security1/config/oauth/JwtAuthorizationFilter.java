package com.example.security1.config.oauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.JwtUtils;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private UserRepository userRepository;
    private JwtUtils jwtUtils;

    public JwtAuthorizationFilter(UserRepository userRepository, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("JwtAuthorizationFilter.JwtAuthorizationFilter");

        //JWT 토큰 검증
        String jwtToken = jwtUtils.getToken(request.getHeader("Authorization"));

        if(jwtToken!=null){
            String username = jwtUtils.getUsername(jwtToken, jwtUtils.ACCESS);

            //서명이 정상적으로 된 경우
            if (username != null) {
                User userEntity = userRepository.findByUsername(username);

                PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

                //jwt 토큰 서명을 통해 만든 객체 (jwtAuthenticationFilter에서 로그인을 통해 만든 방식과는 다름)
                //서명이 정상적으로 됐으므로 사용자라는 근거가 있어 만들 수 있음
                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());


                //SecurityContextHolder.getContext(): 시큐리티 세션 공간을 반환
                //시큐리티 세션에 authentication이 들어있음은 유저가 인증이 되었음을 의미
                //또한 시큐리티 세션 authentication이 들어가야 시큐리티가 인식하여 로직에 사용하며 컨트롤러단에서도 참조할 수 있음 (저장소 역할)
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}
