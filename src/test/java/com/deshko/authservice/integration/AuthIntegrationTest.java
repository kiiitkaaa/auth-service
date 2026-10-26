package com.deshko.authservice.integration;

import com.deshko.authservice.config.TestContainersConfig;
import com.deshko.authservice.entity.Role;
import com.deshko.authservice.entity.UserCredentials;
import com.deshko.authservice.repository.UserCredentialsRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.http.MediaType;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestContainersConfig.class)
class AuthIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired UserCredentialsRepository repo;
    @Autowired JwtDecoder jwtDecoder;

    private static final AtomicLong SEQ = new AtomicLong(1000);

    private long nextUserId() {
        return SEQ.incrementAndGet();
    }

    private String nextLogin(String prefix) {
        return prefix + SEQ.incrementAndGet();
    }

    @Test
    void saveCredentials_storesBcryptHash_andRoleUser() throws Exception {
        long userId = nextUserId();
        String login = nextLogin("alice");

        register(userId, login, "password123").andExpect(status().isCreated());

        UserCredentials saved = repo.findByLogin(login).orElseThrow();
        assertThat(saved.getUserId()).isEqualTo(userId);
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(saved.getPasswordHash())
                .isNotEqualTo("password123")
                .startsWith("$2")
                .hasSize(60);
    }

    @Test
    void saveCredentials_samePassword_differentHashes() throws Exception {
        String login1 = nextLogin("salt");
        String login2 = nextLogin("salt");
        register(nextUserId(), login1, "password123").andExpect(status().isCreated());
        register(nextUserId(), login2, "password123").andExpect(status().isCreated());

        String hash1 = repo.findByLogin(login1).orElseThrow().getPasswordHash();
        String hash2 = repo.findByLogin(login2).orElseThrow().getPasswordHash();

        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    void saveCredentials_roleInRequestIsIgnored() throws Exception {
        String login = nextLogin("sneaky");

        mvc.perform(post("/api/v1/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"userId": %d, "login": "%s", "password": "password123", "role": "ADMIN"}
                                """.formatted(nextUserId(), login)))
                .andExpect(status().isCreated());

        assertThat(repo.findByLogin(login).orElseThrow().getRole()).isEqualTo(Role.USER);
    }

    @Test
    void saveCredentials_duplicateLogin_returns409() throws Exception {
        String login = nextLogin("dup");
        register(nextUserId(), login, "password123").andExpect(status().isCreated());

        register(nextUserId(), login, "password123").andExpect(status().isConflict());
    }

    @Test
    void saveCredentials_duplicateUserId_returns409() throws Exception {
        long userId = nextUserId();
        register(userId, nextLogin("one"), "password123").andExpect(status().isCreated());

        register(userId, nextLogin("two"), "password123").andExpect(status().isConflict());
    }

    @ParameterizedTest
    @CsvSource({
            "ab,password123",
            "validlogin,short"
    })
    void saveCredentials_invalidBody_returns400(String login, String password) throws Exception {
        register(nextUserId(), login, password).andExpect(status().isBadRequest());
    }

    @Test
    void login_returnsTokens_withUserIdAndRole() throws Exception {
        long userId = nextUserId();
        String login = nextLogin("bob");
        register(userId, login, "password123").andExpect(status().isCreated());

        String body = login(login, "password123")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        Jwt access = jwtDecoder.decode(JsonPath.read(body, "$.accessToken"));
        assertThat(access.getSubject()).isEqualTo(String.valueOf(userId));
        assertThat(access.getClaimAsString("role")).isEqualTo("USER");
        assertThat(access.getClaimAsString("type")).isEqualTo("access");
        assertThat(access.getExpiresAt()).isAfter(Instant.now());

        Jwt refresh = jwtDecoder.decode(JsonPath.read(body, "$.refreshToken"));
        assertThat(refresh.getSubject()).isEqualTo(String.valueOf(userId));
        assertThat(refresh.getClaimAsString("type")).isEqualTo("refresh");
        assertThat(refresh.getExpiresAt()).isAfter(access.getExpiresAt());
    }

    @Test
    void login_wrongPassword_returns401() throws Exception {
        String login = nextLogin("carol");
        register(nextUserId(), login, "password123").andExpect(status().isCreated());
        login(login, "wrong-password").andExpect(status().isUnauthorized());
    }

    @Test
    void login_unknownLogin_returns401() throws Exception {
        login("nobody-" + nextUserId(), "password123").andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_withRefreshToken_returnsNewPair() throws Exception {
        String login = nextLogin("erin");
        register(nextUserId(), login, "password123").andExpect(status().isCreated());
        String refresh = tokens(login, "password123").refresh();

        refreshRequest(refresh)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void refresh_withAccessToken_returns401() throws Exception {
        String login = nextLogin("frank");
        register(nextUserId(), login, "password123").andExpect(status().isCreated());
        String access = tokens(login, "password123").access();

        refreshRequest(access).andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_garbageToken_returns401() throws Exception {
        refreshRequest("not-a-jwt").andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_blankToken_returns400() throws Exception {
        refreshRequest("").andExpect(status().isBadRequest());
    }

    @Test
    void validate_validToken_returnsUserIdAndRole() throws Exception {
        long userId = nextUserId();
        String login = nextLogin("heidi");
        register(userId, login, "password123").andExpect(status().isCreated());
        String access = tokens(login, "password123").access();

        validateRequest(access)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(userId))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void validate_garbageToken_returnsValidFalse() throws Exception {
        validateRequest("not-a-jwt")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void validate_tamperedSignature_returnsValidFalse() throws Exception {
        String login = nextLogin("ivan");
        register(nextUserId(), login, "password123").andExpect(status().isCreated());
        String access = tokens(login, "password123").access();
        String tampered = access.substring(0, access.lastIndexOf('.') + 1) + "invalidsignature";

        validateRequest(tampered)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void fullFlow_register_login_refresh_validate() throws Exception {
        long userId = nextUserId();
        String login = nextLogin("judy");

        register(userId, login, "password123").andExpect(status().isCreated());
        Tokens first = tokens(login, "password123");

        String refreshed = refreshRequest(first.refresh())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String newAccess = JsonPath.read(refreshed, "$.accessToken");

        validateRequest(newAccess)
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(userId))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    private record Tokens(String access, String refresh) {}

    private Tokens tokens(String login, String password) throws Exception {
        String body = login(login, password).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new Tokens(JsonPath.read(body, "$.accessToken"),
                JsonPath.read(body, "$.refreshToken"));
    }

    private ResultActions register(long userId, String login, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/credentials")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"userId": %d, "login": "%s", "password": "%s"}
                        """.formatted(userId, login, password)));
    }

    private ResultActions login(String login, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"login": "%s", "password": "%s"}
                        """.formatted(login, password)));
    }

    private ResultActions refreshRequest(String token) throws Exception {
        return mvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"refreshToken": "%s"}
                        """.formatted(token)));
    }

    private ResultActions validateRequest(String token) throws Exception {
        return mvc.perform(post("/api/v1/auth/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"token": "%s"}
                        """.formatted(token)));
    }
}
