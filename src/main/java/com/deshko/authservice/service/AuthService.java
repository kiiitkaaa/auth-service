package com.deshko.authservice.service;

import com.deshko.authservice.dto.*;
import com.deshko.authservice.entity.Role;
import com.deshko.authservice.entity.UserCredentials;
import com.deshko.authservice.exception.CredentialsAlreadyExistException;
import com.deshko.authservice.repository.UserCredentialsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserCredentialsRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtDecoder jwtDecoder;

    @Transactional
    public void saveCredentials(SaveCredentialsRequest req) {
        if (repo.existsByLogin(req.login()) || repo.existsByUserId(req.userId())) {
            throw new CredentialsAlreadyExistException("Credentials already exist");
        }
        UserCredentials c = new UserCredentials();
        c.setUserId(req.userId());
        c.setLogin(req.login());
        c.setPasswordHash(passwordEncoder.encode(req.password()));
        c.setRole(Role.USER);
        repo.save(c);
    }

    @Transactional(readOnly = true)
    public TokenPair login(LoginRequest req) {
        UserCredentials c = repo.findByLogin(req.login())
                .filter(x -> passwordEncoder.matches(req.password(), x.getPasswordHash()))
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));
        return issueTokens(c);
    }

    @Transactional(readOnly = true)
    public TokenPair refresh(RefreshRequest req) {
        Jwt token = jwtDecoder.decode(req.refreshToken());
        if (!"refresh".equals(token.getClaimAsString("type"))) {
            throw new BadCredentialsException("Not a refresh token");
        }
        UserCredentials c = repo.findByUserId(Long.valueOf(token.getSubject()))
                .orElseThrow(() -> new BadCredentialsException("User is not active"));
        return issueTokens(c);
    }

    public ValidateResponse validate(ValidateRequest req) {
        try {
            Jwt token = jwtDecoder.decode(req.token());
            return new ValidateResponse(true, Long.valueOf(token.getSubject()),
                    token.getClaimAsString("role"));
        } catch (JwtException e) {
            return new ValidateResponse(false, null, null);
        }
    }

    private TokenPair issueTokens(UserCredentials c) {
        return new TokenPair(jwtService.createAccessToken(c), jwtService.createRefreshToken(c));
    }
}
