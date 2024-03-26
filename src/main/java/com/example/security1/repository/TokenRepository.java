package com.example.security1.repository;

import com.example.security1.model.RefreshToken;
import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.List;

public interface TokenRepository extends JpaRepository<RefreshToken, Long> {

    public String findByToken(String token);

    @Query("DELETE FROM RefreshToken r  WHERE r.username=:username")
    public void expireToken(String username);

    List<RefreshToken> findByExpiryDateBefore(LocalDateTime expiryDate);
}
