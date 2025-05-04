package com.sakcode.securityone.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import com.sakcode.securityone.handler.RateLimitExceededException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
public class RateLimitConfig {
    private final ConcurrentHashMap<String, Bucket> adminBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> userBuckets = new ConcurrentHashMap<>();

    private static final long ADMIN_REQUESTS = 100; // 100 requests
    private static final Duration ADMIN_REFILL_TIME = Duration.ofMinutes(1); // per minute
    private static final long USER_REQUESTS = 3; // 1000 requests
    private static final Duration USER_REFILL_TIME = Duration.ofMinutes(1); // per minute

    @Bean
    public OrRequestMatcher adminRateLimitMatcher() {
        return new OrRequestMatcher(
            new AntPathRequestMatcher("/api/admin/**"),
            new AntPathRequestMatcher("/api/test/admin/**")
        );
    }

    @Bean
    public OrRequestMatcher userRateLimitMatcher() {
        return new OrRequestMatcher(
            new AntPathRequestMatcher("/api/auth/**"),
            new AntPathRequestMatcher("/api/user/**"),
            new AntPathRequestMatcher("/api/test/user/**")
        );
    }

    public Bucket createAdminBucket() {
        return Bucket4j.builder()
                .addLimit(Bandwidth.classic(ADMIN_REQUESTS, Refill.intervally(ADMIN_REQUESTS, ADMIN_REFILL_TIME)))
                .build();
    }

    public Bucket createUserBucket() {
        return Bucket4j.builder()
                .addLimit(Bandwidth.classic(USER_REQUESTS, Refill.intervally(USER_REQUESTS, USER_REFILL_TIME)))
                .build();
    }

    public RateLimitResult isRateLimited(String ipAddress, AntPathRequestMatcher request) {
        boolean isAdmin = request.getPattern().startsWith("/api/admin/") || 
                        request.getPattern().startsWith("/api/test/admin/");
        
        Map<String, Bucket> bucketMap = isAdmin ? adminBuckets : userBuckets;
        Bucket bucket = bucketMap.computeIfAbsent(ipAddress, k -> 
            isAdmin ? createAdminBucket() : createUserBucket());

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (!probe.isConsumed()) {
            long waitTime = probe.getNanosToWaitForRefill() / 1_000_000_000;
            return new RateLimitResult(false, String.format("Too many requests. Please try again in %d seconds", waitTime));
        }
        return new RateLimitResult(true, null);
    }
}
