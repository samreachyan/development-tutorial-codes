package com.sakcode.securityone.controller;

import com.sakcode.securityone.dto.request.LoginRequest;
import com.sakcode.securityone.dto.request.RefreshTokenRequest;
import com.sakcode.securityone.dto.request.RegisterRequest;
import com.sakcode.securityone.dto.request.MfaVerificationRequest;
import com.sakcode.securityone.dto.response.JwtResponse;
import com.sakcode.securityone.dto.response.MessageResponse;
import com.sakcode.securityone.dto.response.MfaVerificationResponse;
import com.sakcode.securityone.dto.response.RefreshTokenResponse;
import com.sakcode.securityone.entity.RefreshToken;
import com.sakcode.securityone.entity.User;
import com.sakcode.securityone.entity.MfaSession;
import com.sakcode.securityone.handler.TokenRefreshException;
import com.sakcode.securityone.service.*;
import com.sakcode.securityone.repository.MfaSessionRepository;
import com.sakcode.securityone.repository.UserRepository;
import com.sakcode.securityone.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final UserService userService;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenService refreshTokenService;
    private final MfaSessionService mfaSessionService;
    private final MfaSessionRepository mfaSessionRepository;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, TokenBlacklistService tokenBlacklistService, RefreshTokenService refreshTokenService, MfaSessionService mfaSessionService, MfaSessionRepository mfaSessionRepository, UserRepository userRepository, AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.userService = userService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.refreshTokenService = refreshTokenService;
        this.mfaSessionService = mfaSessionService;
        this.mfaSessionRepository = mfaSessionRepository;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();

        if (mfaSessionService.findByUserId(user.getId()) != null) {
            MfaVerificationResponse response = mfaSessionService.createMfaSession(user.getUsername());
            return ResponseEntity.ok(response);
        }

        String jwt = jwtUtil.generateToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return ResponseEntity.ok(new JwtResponse(
                jwt,
                refreshToken.getToken(),
                user.getId(),
                user.getUsername()));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        User user = userService.registerUser(
                registerRequest.getUsername(),
                registerRequest.getPassword(),
                registerRequest.getEmail(),
                registerRequest.getRole());
        log.info("User created for {} - {}", user.getEmail(), user.getUsername());

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@Valid @RequestBody MfaVerificationRequest request) {
        // Verify MFA session
        Optional<MfaSession> sessionOpt = mfaSessionRepository.findBySessionId(request.getSessionId());
        if (sessionOpt.isEmpty() || sessionOpt.get().isUsed() || sessionOpt.get().isExpired()) {
            return ResponseEntity.badRequest().body("Invalid or expired session");
        }

        // Verify TOTP code
        Optional<String> usernameOpt = mfaSessionRepository.findUsernameBySessionId(request.getSessionId());
        if (usernameOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        String username = usernameOpt.get();
        boolean isValid = mfaSessionService.verifyMfa(request);
        if (!isValid) {
            return ResponseEntity.badRequest().body("Invalid TOTP code");
        }

        // Authenticate user
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT token
        String jwt = jwtUtil.generateToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return ResponseEntity.ok(new JwtResponse(
                jwt,
                refreshToken.getToken(),
                user.getId(),
                user.getUsername()));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtil.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new RefreshTokenResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String authHeader) {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // Invalidate refresh token
        refreshTokenService.deleteByUserId(userDetails.getId());

        // Invalidate JWT token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);
            tokenBlacklistService.blacklistToken(jwt);
        }

        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }
}