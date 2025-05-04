package com.sakcode.securityone.service;

import com.sakcode.securityone.dto.request.MfaVerificationRequest;
import com.sakcode.securityone.dto.response.MfaVerificationResponse;
import com.sakcode.securityone.entity.MfaSession;
import com.sakcode.securityone.entity.MfaSettings;
import com.sakcode.securityone.entity.User;
import com.sakcode.securityone.repository.MfaSettingsRepository;
import com.sakcode.securityone.repository.MfaSessionRepository;
import com.sakcode.securityone.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MfaSessionService {
    private final MfaService mfaService;
    private final UserRepository userRepository;
    private final MfaSettingsRepository mfaSettingsRepository;
    private final MfaSessionRepository mfaSessionRepository;

    private static final long SESSION_EXPIRATION_MINUTES = 5;

    @Transactional
    public MfaVerificationResponse createMfaSession(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        MfaSettings mfaSettings = findByUserId(user.getId());
        if (mfaSettings == null || !mfaSettings.isEnabled()) {
            return null;
        }

        // Clean up expired sessions
        mfaSessionRepository.deleteByExpirationTimeBefore(Instant.now());

        // Check if there's an existing unused session for this user
        Optional<MfaSession> existingSession = mfaSessionRepository.findByUserIdAndAndUsedFalse(user.getId());
        if (existingSession.isPresent()) {
            return new MfaVerificationResponse(existingSession.get().getSessionId(), "MFA verification session created");
        }

        String sessionId = UUID.randomUUID().toString();
        MfaSession session = new MfaSession();
        session.setSessionId(sessionId);
        session.setUser(user);
        session.setExpirationTime(Instant.now().plusSeconds(SESSION_EXPIRATION_MINUTES * 60));
        session.setUsed(false);

        mfaSessionRepository.save(session);

        return new MfaVerificationResponse(sessionId, "MFA verification session created");
    }

    public boolean verifyMfa(MfaVerificationRequest request) {
        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionId(request.getSessionId());
        if (sessionOpt.isEmpty() || sessionOpt.get().isUsed() || sessionOpt.get().isExpired()) {
            throw new RuntimeException("Invalid or expired session");
        }

        MfaSession session = sessionOpt.get();
        User user = session.getUser();

        MfaSettings mfaSettings = findByUserId(user.getId());
        if (mfaSettings == null || !mfaSettings.isEnabled()) {
            throw new RuntimeException("MFA is not enabled for this user");
        }

        boolean isValid = mfaService.verifyCode(user.getUsername(), request.getCode());
        if (isValid) {
            session.setUsed(true);
            mfaSessionRepository.save(session);
        }

        return isValid;
    }

    public MfaSettings findByUserId(Long userId) {
        return mfaSettingsRepository.findByUserId(userId);
    }


}
