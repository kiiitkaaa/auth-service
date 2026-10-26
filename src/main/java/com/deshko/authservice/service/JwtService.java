package com.deshko.authservice.service;

import com.deshko.authservice.entity.UserCredentials;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
class JwtService {
    private final JwtEncoder encoder;

    @Value("${jwt.access-ttl:PT15M}")
    Duration accessTtl;

    @Value("${jwt.refresh-ttl:P7D}")
    Duration refreshTtl;

    String createAccessToken(UserCredentials c) {
        return build(c, "access", accessTtl);
    }

    String createRefreshToken(UserCredentials c) {
        return build(c, "refresh", refreshTtl);
    }

    private String build(UserCredentials c, String type, Duration ttl) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(String.valueOf(c.getUserId()))
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim("role", c.getRole().name())
                .claim("type", type)
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}