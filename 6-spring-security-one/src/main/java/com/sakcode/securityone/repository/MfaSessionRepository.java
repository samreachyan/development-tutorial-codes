package com.sakcode.securityone.repository;

import com.sakcode.securityone.entity.MfaSession;
import com.sakcode.securityone.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface MfaSessionRepository extends JpaRepository<MfaSession, String> {
    Optional<MfaSession> findBySessionId(String sessionId);
    Optional<MfaSession> findByUserIdAndAndUsedFalse(Long userId);
    void deleteByExpirationTimeBefore(Instant time);

    @Query("SELECT u.username FROM User u JOIN MfaSession ms ON u.id = ms.user.id WHERE ms.sessionId = :sessionId")
    Optional<String> findUsernameBySessionId(String sessionId);
}
