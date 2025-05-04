package com.sakcode.securityone.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "mfa_settings")
public class MfaSettings {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String secretKey;
    private boolean enabled;
    @Column(length = 2000)
    private String qrCodeData;
    private String issuer;
    private String accountName;

    public MfaSettings() {
        this.enabled = false;
    }
}
