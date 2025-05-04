package com.sakcode.securityone.entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.Instant;

@Data
@Entity
@Table(name = "mfa_sessions")
public class MfaSession {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String sessionId;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "expiration_time")
    private Instant expirationTime;

    @Column(name = "is_used")
    private boolean used;

    public boolean isExpired() {
        return Instant.now().isAfter(expirationTime);
    }
}
