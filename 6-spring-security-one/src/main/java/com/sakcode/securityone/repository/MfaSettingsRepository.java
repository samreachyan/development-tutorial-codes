package com.sakcode.securityone.repository;

import com.sakcode.securityone.entity.MfaSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MfaSettingsRepository extends JpaRepository<MfaSettings, Long> {
    MfaSettings findByUser_Username(String username);
    MfaSettings findByUserId(Long userId);
}
