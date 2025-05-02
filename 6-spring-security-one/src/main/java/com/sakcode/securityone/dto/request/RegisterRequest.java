package com.sakcode.securityone.dto.request;

import java.util.Set;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String password;
    private String email;
    private Set<String> role;

}
