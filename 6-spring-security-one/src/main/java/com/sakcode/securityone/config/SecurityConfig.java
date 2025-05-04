package com.sakcode.securityone.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.config.Customizer;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthEntryPoint unauthorizedHandler;
    private final JwtAuthFilter jwtAuthFilter;
    private final IpSecurityConfig ipSecurityConfig;
    private final RateLimitConfig rateLimitConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/api/auth/**").permitAll()
                                .requestMatchers("/api/mfa/**").hasRole("USER")
                                .requestMatchers("/api/test/admin/**").hasRole("ADMIN")
                                .requestMatchers("/api/test/user/**").hasAnyRole("USER", "ADMIN")
                                .requestMatchers("/api/test/all/**").hasAnyRole("USER", "ADMIN")
                                .anyRequest().authenticated());

        // Add IP security
//        http.addFilterBefore(new IpSecurityFilter(ipSecurityConfig), UsernamePasswordAuthenticationFilter.class);
        
        // Add rate limiting
        http.addFilterBefore(new RateLimitFilter(rateLimitConfig), UsernamePasswordAuthenticationFilter.class);

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // Custom filters
    public class IpSecurityFilter extends OncePerRequestFilter {
        private final IpSecurityConfig ipSecurityConfig;

        public IpSecurityFilter(IpSecurityConfig ipSecurityConfig) {
            this.ipSecurityConfig = ipSecurityConfig;
        }

        @Override
        protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {
            if (!IpSecurityConfig.xForwardedForMatcher().matches(request)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid X-Forwarded-For header");
                return;
            }
            filterChain.doFilter(request, response);
        }
    }

    public class RateLimitFilter extends OncePerRequestFilter {
        private final RateLimitConfig rateLimitConfig;

        public RateLimitFilter(RateLimitConfig rateLimitConfig) {
            this.rateLimitConfig = rateLimitConfig;
        }

        @Override
        protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, IOException {
            String ipAddress = request.getHeader("X-Forwarded-For");
            RateLimitResult result = rateLimitConfig.isRateLimited(ipAddress, new AntPathRequestMatcher(request.getRequestURI()));
            
            if (!result.isAllowed()) {
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write("{" + 
                    "\"timestamp\":\"" + java.time.LocalDateTime.now() + "\"," +
                    "\"status\":429," +
                    "\"error\":\"Too Many Requests\"," +
                    "\"message\":\"" + result.getErrorMessage() + "\"," +
                    "\"path\":\"" + request.getRequestURI() + "\"" +
                    "}");
                return;
            }
            filterChain.doFilter(request, response);
        }
    }

}
