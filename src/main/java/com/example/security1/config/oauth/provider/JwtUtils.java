package com.example.security1.config.oauth.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.config.auth.PrincipalDetails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    public static final String ACCESS = "access";
    public static final String REFRESH = "refresh";

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration.access}")
    private long accessTokenExpiration;

    @Value("${jwt.expiration.refresh}")
    private long refreshTokenExpiration;

    public String getToken(String header){
        if(header == null || !header.startsWith("Bearer")){
            return null;
        }
        return header.replace("Bearer ", "");
    }

    public String generateAccessToken(PrincipalDetails principalDetails){
        return createToken(principalDetails.getUsername(),accessTokenExpiration, ACCESS);
    }

    public String generateRefreshToken(PrincipalDetails principalDetails){
        return createToken(principalDetails.getUsername(), refreshTokenExpiration, REFRESH);
    }

    private String createToken(String username, Long time, String type){
        return JWT.create()
                .withSubject(type + "Token")    //token subject 이름(큰 의미 없음)
                .withExpiresAt(new Date(System.currentTimeMillis() + time))   //만기 시간
                .withClaim("username", username)
                .sign(Algorithm.HMAC512(type + jwtSecret)); //시크릿 키값과 시크니쳐 암호화 방식 설정
    }


    public String getUsername(String token, String type){
        try {
            return JWT.require(Algorithm.HMAC512(type+jwtSecret))
                    .build().verify(token).getClaim("username").asString();
        }catch (Exception e){
            return null;
        }
    }
}
