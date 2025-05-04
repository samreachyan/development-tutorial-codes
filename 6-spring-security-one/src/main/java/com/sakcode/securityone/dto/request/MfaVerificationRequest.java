package com.sakcode.securityone.dto.request;

import lombok.Data;

@Data
public class MfaVerificationRequest {
    private String sessionId;
    private String code;
}
