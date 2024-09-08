package com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.service;

import com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.controller.AuthenticationRequest;
import com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.controller.AuthenticationResponse;
import com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.controller.RegisterRequest;
import com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.model.User;
import com.example.springsecurityratelimiterapi.springsecurityratelimiterapi.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public String register(RegisterRequest request){
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        repository.save(user);

        return "User Registered Successfully";
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        User user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
