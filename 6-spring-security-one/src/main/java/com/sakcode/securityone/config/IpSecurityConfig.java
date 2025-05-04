package com.sakcode.securityone.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Primary;

import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class IpSecurityConfig {

    private static final List<String> TRUSTED_PROXIES = Arrays.asList(
        "127.0.0.1",  // Localhost
        "127.0.0.2",
        "10.0.0.0/8", // Private networks
        "172.16.0.0/12",
        "192.168.0.0/16"
    );

    @Bean
    @Primary
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }

    public static boolean isTrustedProxy(String remoteAddr) {
        for (String trustedProxy : TRUSTED_PROXIES) {
            if (trustedProxy.equals(remoteAddr) || trustedProxy.startsWith(remoteAddr + "/")) {
                return true;
            }
        }
        return false;
    }

    public static RequestMatcher xForwardedForMatcher() {
        return new RequestMatcher() {
            @Override
            public boolean matches(jakarta.servlet.http.HttpServletRequest request) {
                String xForwardedFor = request.getHeader("X-Forwarded-For");
//                String remoteAddr = request.getRemoteAddr();

                // Check if X-Forwarded-For is present and remote address is trusted
                return xForwardedFor != null && isTrustedProxy(xForwardedFor);
            }
        };
    }
}
