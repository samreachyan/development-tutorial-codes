package com.sakcode.securityone.service;

import com.sakcode.securityone.entity.User;
import com.sakcode.securityone.handler.InvalidDataException;
import com.sakcode.securityone.handler.ResourceAlreadyExistsException;
import com.sakcode.securityone.handler.ResourceNotFoundException;
import com.sakcode.securityone.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(String username, String password, String email, Set<String> roles) {
        // Validate username uniqueness
        if (userRepository.existsByUsername(username)) {
            throw new ResourceAlreadyExistsException("Username is already taken");
        }

        // Validate email uniqueness
        if (userRepository.existsByEmail(email)) {
            throw new ResourceAlreadyExistsException("Email is already registered");
        }

        // Validate password strength
        if (password == null || password.length() < 8) {
            throw new InvalidDataException("Password must be at least 8 characters long");
        }

        // Validate email format
        if (!isValidEmail(email)) {
            throw new InvalidDataException("Invalid email format");
        }

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .roles(roles)
                .enabled(true)
                .build();

        return userRepository.save(user);
    }

    private boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PreAuthorize("#username == authentication.principal.username or hasRole('ADMIN')")
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        
        return UserDetailsImpl.build(user);
    }
}
