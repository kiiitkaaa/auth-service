package com.deshko.authservice.service;

import com.deshko.authservice.dto.*;
import com.deshko.authservice.entity.Role;
import com.deshko.authservice.entity.UserCredentials;
import com.deshko.authservice.exception.CredentialsAlreadyExistException;
import com.deshko.authservice.repository.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock UserCredentialsRepository repo;
    @Mock JwtService jwtService;
    @Mock JwtDecoder jwtDecoder;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(repo, passwordEncoder, jwtService, jwtDecoder);
    }

    @Test
    void saveCredentials_hashesPasswordAndForcesUserRole() {
        when(repo.existsByLogin("alice")).thenReturn(false);
        when(repo.existsByUserId(10L)).thenReturn(false);

        authService.saveCredentials(new SaveCredentialsRequest(10L, "alice",
                "password123"));

        ArgumentCaptor<UserCredentials> captor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(repo).save(captor.capture());
        UserCredentials saved = captor.getValue();

        assertThat(saved.getUserId()).isEqualTo(10L);
        assertThat(saved.getLogin()).isEqualTo("alice");
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(saved.getPasswordHash())
                .isNotEqualTo("password123")
                .startsWith("$2")
                .hasSize(60);
        assertThat(passwordEncoder.matches("password123", saved.getPasswordHash())).isTrue();
    }

    @Test
    void saveCredentials_samePasswordGivesDifferentHashes() {
        authService.saveCredentials(new SaveCredentialsRequest(1L, "user1",
                "password123"));
        authService.saveCredentials(new SaveCredentialsRequest(2L, "user2",
                "password123"));

        ArgumentCaptor<UserCredentials> captor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(repo, times(2)).save(captor.capture());

        assertThat(captor.getAllValues().get(0).getPasswordHash())
                .isNotEqualTo(captor.getAllValues().get(1).getPasswordHash());
    }

    @Test
    void saveCredentials_duplicateLogin_throws() {
        when(repo.existsByLogin("alice")).thenReturn(true);

        assertThatThrownBy(() ->
                authService.saveCredentials(new SaveCredentialsRequest(10L,
                        "alice", "password123")))
                .isInstanceOf(CredentialsAlreadyExistException.class);

        verify(repo, never()).save(any());
    }

    @Test
    void saveCredentials_duplicateUserId_throws() {
        when(repo.existsByLogin("bob")).thenReturn(false);
        when(repo.existsByUserId(10L)).thenReturn(true);

        assertThatThrownBy(() ->
                authService.saveCredentials(new SaveCredentialsRequest(10L,
                        "bob", "password123")))
                .isInstanceOf(CredentialsAlreadyExistException.class);
    }

    @Test
    void login_success_returnsTokens() {
        UserCredentials c = credentials(10L, "alice", "password123", Role.USER);
        when(repo.findByLogin("alice")).thenReturn(Optional.of(c));
        when(jwtService.createAccessToken(c)).thenReturn("access");
        when(jwtService.createRefreshToken(c)).thenReturn("refresh");

        TokenPair pair = authService.login(new LoginRequest("alice", "password123"));

        assertThat(pair.accessToken()).isEqualTo("access");
        assertThat(pair.refreshToken()).isEqualTo("refresh");
    }

    @Test
    void login_wrongPassword_throwsBadCredentials() {
        when(repo.findByLogin("alice"))
                .thenReturn(Optional.of(credentials(10L, "alice",
                        "password123", Role.USER)));

        assertThatThrownBy(() -> authService.login(new LoginRequest("alice", "wrong")))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(jwtService);
    }

    @Test
    void login_unknownLogin_throwsBadCredentials() {
        when(repo.findByLogin("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("ghost", "password123")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void refresh_validRefreshToken_returnsNewPair() {
        UserCredentials c = credentials(10L, "alice", "password123", Role.USER);
        when(jwtDecoder.decode("old-refresh")).thenReturn(jwt("10", "refresh"));
        when(repo.findByUserId(10L)).thenReturn(Optional.of(c));
        when(jwtService.createAccessToken(c)).thenReturn("new-access");
        when(jwtService.createRefreshToken(c)).thenReturn("new-refresh");

        TokenPair pair = authService.refresh(new RefreshRequest("old-refresh"));

        assertThat(pair.accessToken()).isEqualTo("new-access");
        assertThat(pair.refreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void refresh_accessTokenInsteadOfRefresh_throws() {
        when(jwtDecoder.decode("access")).thenReturn(jwt("10", "access"));

        assertThatThrownBy(() -> authService.refresh(new RefreshRequest("access")))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(repo);
    }

    @Test
    void refresh_invalidToken_propagatesJwtException() {
        when(jwtDecoder.decode("garbage")).thenThrow(new BadJwtException("bad"));

        assertThatThrownBy(() -> authService.refresh(new RefreshRequest("garbage")))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void validate_validToken_returnsUserIdAndRole() {
        when(jwtDecoder.decode("t")).thenReturn(jwt("10", "access", "ADMIN"));

        ValidateResponse r = authService.validate(new ValidateRequest("t"));

        assertThat(r.valid()).isTrue();
        assertThat(r.userId()).isEqualTo(10L);
        assertThat(r.role()).isEqualTo("ADMIN");
    }

    @Test
    void validate_invalidToken_returnsValidFalse() {
        when(jwtDecoder.decode("bad")).thenThrow(new BadJwtException("bad"));

        ValidateResponse r = authService.validate(new ValidateRequest("bad"));

        assertThat(r.valid()).isFalse();
        assertThat(r.userId()).isNull();
        assertThat(r.role()).isNull();
    }

    private UserCredentials credentials(Long userId, String login, String rawPassword, Role role) {
        UserCredentials c = new UserCredentials();
        c.setUserId(userId);
        c.setLogin(login);
        c.setPasswordHash(passwordEncoder.encode(rawPassword));
        c.setRole(role);
        return c;
    }

    private Jwt jwt(String subject, String type) {
        return jwt(subject, type, "USER");
    }

    private Jwt jwt(String subject, String type, String role) {
        return Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject(subject)
                .claim("type", type)
                .claim("role", role)
                .build();
    }
}
