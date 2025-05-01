package com.sakcode.securityone.service;

import com.sakcode.securityone.entity.BlacklistedToken;
import com.sakcode.securityone.repository.BlacklistedTokenRepository;
import com.sakcode.securityone.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private final JwtUtil jwtUtil;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public void blacklistToken(String token) {
        if (jwtUtil.validateJwtToken(token)) {
            Instant expiryDate = jwtUtil.getExpirationDateFromToken(token);
            BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                    .token(token)
                    .expiryDate(expiryDate)
                    .build();
            blacklistedTokenRepository.save(blacklistedToken);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokenRepository.findByToken(token).isPresent();
    }

    @Scheduled(fixedRate = 3600000) // Run every hour
    public void cleanupExpiredTokens() {
        blacklistedTokenRepository.deleteExpiredTokens(Instant.now());
    }
}
