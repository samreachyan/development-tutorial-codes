package com.sakcode.securityone.config;

public class RateLimitResult {
    private final boolean isAllowed;
    private final String errorMessage;

    public RateLimitResult(boolean isAllowed, String errorMessage) {
        this.isAllowed = isAllowed;
        this.errorMessage = errorMessage;
    }

    public boolean isAllowed() {
        return isAllowed;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}