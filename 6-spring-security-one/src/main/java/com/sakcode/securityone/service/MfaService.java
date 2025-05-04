package com.sakcode.securityone.service;

import com.sakcode.securityone.entity.MfaSettings;
import com.sakcode.securityone.entity.User;
import com.sakcode.securityone.repository.MfaSettingsRepository;
import com.sakcode.securityone.repository.UserRepository;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@RequiredArgsConstructor
public class MfaService {
    protected final MfaSettingsRepository mfaSettingsRepository;
    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(20);
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();

    public MfaSettings findByUserId(Long userId) {
        return mfaSettingsRepository.findByUserId(userId);
    }

    @Transactional
    public MfaSettings setupMfa(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        MfaSettings mfaSettings = mfaSettingsRepository.findByUserId(user.getId());
        if (mfaSettings == null) {
            mfaSettings = new MfaSettings();
            mfaSettings.setUser(user);
        }

        String secret = secretGenerator.generate();
        mfaSettings.setSecretKey(secret);
        mfaSettings.setEnabled(false);
        mfaSettings.setIssuer("Sakcode");
        mfaSettings.setAccountName(user.getUsername());

        QrData qrData = new QrData.Builder()
                .label(user.getUsername())
                .secret(secret)
                .issuer("Sakcode")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(60)
                .build();

        try {
            byte[] qrCodeBytes = qrGenerator.generate(qrData);
            String qrCode = Base64.getEncoder().encodeToString(qrCodeBytes);
            mfaSettings.setQrCodeData(qrCode);
        } catch (QrGenerationException e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }

        return mfaSettingsRepository.save(mfaSettings);
    }

    @Transactional
    public boolean verifyCode(String username, String code) {
        MfaSettings mfaSettings = mfaSettingsRepository.findByUser_Username(username);
        if (mfaSettings == null) {
            throw new RuntimeException("MFA settings not found");
        }

        return verifier.isValidCode(mfaSettings.getSecretKey(), code);
    }

    @Transactional
    public void enableMfa(String username) {
        MfaSettings mfaSettings = mfaSettingsRepository.findByUser_Username(username);
        if (mfaSettings == null) {
            throw new RuntimeException("MFA settings not found");
        }

        mfaSettings.setEnabled(true);
        mfaSettingsRepository.save(mfaSettings);
    }

    @Transactional
    public void disableMfa(String username) {
        MfaSettings mfaSettings = mfaSettingsRepository.findByUser_Username(username);
        if (mfaSettings == null) {
            throw new RuntimeException("MFA settings not found");
        }

        mfaSettings.setEnabled(false);
        mfaSettingsRepository.save(mfaSettings);
    }

    public boolean isMfaEnabled(String username) {
        MfaSettings mfaSettings = mfaSettingsRepository.findByUser_Username(username);
        return mfaSettings != null && mfaSettings.isEnabled();
    }
}
