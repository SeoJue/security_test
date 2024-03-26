package com.example.security1.controller;
import com.example.security1.model.RefreshToken;
import com.example.security1.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;


@Component
public class TokenCleanupScheduler {
    @Autowired
    private TokenRepository tokenRepository;

    @Scheduled(fixedRate = 3600000) // 매 시간마다 실행
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        List<RefreshToken> expiredTokens = tokenRepository.findByExpiryDateBefore(now);
        tokenRepository.deleteAll(expiredTokens);
    }
}
