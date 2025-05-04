package com.sakcode.securityone.controller;

import com.sakcode.securityone.dto.MfaSetupResponse;
import com.sakcode.securityone.service.MfaService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/mfa")
public class MfaController {
    private final MfaService mfaService;

    public MfaController(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    @GetMapping("/setup")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<MfaSetupResponse> setupMfa() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        com.sakcode.securityone.entity.MfaSettings mfaSettings = mfaService.setupMfa(username);
        return ResponseEntity.ok(new MfaSetupResponse(mfaSettings.getQrCodeData()));
    }

    @PostMapping("/verify")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyCode(@RequestParam String code) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        boolean isValid = mfaService.verifyCode(username, code);
        if (isValid) {
            mfaService.enableMfa(username);
            return ResponseEntity.ok("MFA successfully enabled");
        }
        return ResponseEntity.badRequest().body("Invalid code");
    }

    @PostMapping("/disable")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> disableMfa() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        mfaService.disableMfa(username);
        return ResponseEntity.ok("MFA successfully disabled");
    }
}
