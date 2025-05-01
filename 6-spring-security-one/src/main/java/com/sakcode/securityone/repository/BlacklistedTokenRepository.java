package com.sakcode.securityone.repository;

import com.sakcode.securityone.entity.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
    Optional<BlacklistedToken> findByToken(String token);
    
    @Modifying
    @Query("DELETE FROM BlacklistedToken bt WHERE bt.expiryDate < :now")
    void deleteExpiredTokens(Instant now);
}
