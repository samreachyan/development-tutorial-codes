package com.sakcode.securityone.handler;

public class TokenRefreshException extends RuntimeException {
    public TokenRefreshException(String message) {
        super(message);
    }

    public TokenRefreshException(String token, String s) {
        super(s);
    }
}
