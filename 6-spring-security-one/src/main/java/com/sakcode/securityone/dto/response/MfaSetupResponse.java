package com.sakcode.securityone.dto.response;

import lombok.Data;

@Data
public class MfaSetupResponse {
    private String qrCodeData;

    public MfaSetupResponse(String qrCodeData) {
        this.qrCodeData = qrCodeData;
    }
}
