package com.sakcode.securityone.dto.response;

import lombok.Data;

@Data
public class MfaVerificationResponse {
    private String sessionId;
    private String message;

    public MfaVerificationResponse(String sessionId, String message) {
        this.sessionId = sessionId;
        this.message = message;
    }
}
