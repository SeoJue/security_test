package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.JwtUtils;
import com.example.security1.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class TokenController {


    final private TokenRepository tokenRepository;
    final private JwtUtils jwtUtils;


    @PostMapping("/accessToken")
    public ResponseEntity<String> generateToken(String refreshToken, Authentication authentication){

        if(tokenRepository.findByToken(refreshToken)==null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("401 UnAuthorized");
        }

        String username = jwtUtils.getUsername(refreshToken, jwtUtils.REFRESH);

        if(username==null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("401 UnAuthorized");
        }

        String newToken = jwtUtils.generateAccessToken((PrincipalDetails) authentication.getPrincipal());

        return ResponseEntity.status(HttpStatus.OK).body(newToken);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(String refreshToken){
        String username = jwtUtils.getUsername(refreshToken, jwtUtils.REFRESH);

        if(username==null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("401 UnAuthorized");
        }

        tokenRepository.expireToken(username);

        return ResponseEntity.status(HttpStatus.OK).body("logout success");
    }
}
