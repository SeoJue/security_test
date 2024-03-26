package com.example.security1.config.oauth;

import com.example.security1.config.auth.PrincipalDetails;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.config.oauth.provider.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

import java.awt.*;
import java.io.IOException;
import java.util.Date;

public class MyAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler{

    private JwtUtils jwtUtils;

    public MyAuthenticationSuccessHandler(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        String accessToken = jwtUtils.generateAccessToken(principalDetails);
        String refreshToken = jwtUtils.generateRefreshToken(principalDetails);

        /*
        String jwtToken = JWT.create()
                .withSubject("cosToken")    //token subject 이름(큰 의미 없음)
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000 * 30))   //만기 시간
                .withClaim("id", principalDetails.getUser().getId())    //포함하고 싶은 키 밸류값
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("accesscos")); //시크릿 키값과 시크니쳐 암호화 방식 설정
        */

        //Bearer 방식임을 표시

        String script = "<script>" +
                "var tokens = {" +
                "accessToken: '" + accessToken + "'," +
                "refreshToken: '" + refreshToken + "'" +
                "};" +
                "tokenHandler.postMessage(JSON.stringify(tokens));" +
                "</script>";

        response.addHeader("Authorization", "Bearer "+accessToken);
        response.setContentType("text/html");
        //response.getWriter().write("<script>tokenHandler.postMessage('"+jwtToken+"');</script>");
        response.getWriter().write(script);
    }


}
