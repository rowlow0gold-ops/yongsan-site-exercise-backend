package com.example.demo.auth.controller;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@org.springframework.context.annotation.Import(com.example.demo.config.TestConfig.class)
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.jwt.secret=testsecrettestsecrettestsecrettestsecrettestsecret",
        "app.jwt.accessTtlSeconds=900",
        "app.jwt.refreshTtlSeconds=1209600",
        "app.jwt.refreshCookieName=refresh_token",
        "app.oauth2.redirect-uri=http://localhost:5173",
        "spring.security.oauth2.client.registration.google.client-id=test",
        "spring.security.oauth2.client.registration.google.client-secret=test",
        "spring.security.oauth2.client.registration.google.scope=email,profile",
        "spring.data.redis.host=localhost",
        "spring.data.redis.port=6379",
        // Don't hit the real HIBP service from tests; assume all passwords are safe.
        "app.security.passwordBreachCheck=false",
        // Tests don't run over HTTPS, so don't set the Secure cookie flag
        // (browsers would silently drop the cookie and tests would fail mysteriously).
        "app.cookie.secure=false"
})
class AuthControllerIntegrationTest {

    MockMvc mvc;
    final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    @Autowired AppUserRepository userRepo;
    @Autowired PasswordEncoder encoder;
    @Autowired WebApplicationContext wac;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(springSecurity())
                .build();
        userRepo.deleteAll();
    }

    // ─── Signup ───

    @Test
    @DisplayName("POST /auth/signup — success")
    void signupSuccess() throws Exception {
        mvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "name", "tester",
                                "email", "test@example.com",
                                "password", "password123"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OK"));
    }

    @Test
    @DisplayName("POST /auth/signup — duplicate email returns generic OK (no enumeration)")
    void signupDuplicateEmail() throws Exception {
        AppUser u = new AppUser();
        u.setEmail("dup@example.com");
        u.setName("existing");
        u.setRole("USER");
        u.setPasswordHash(encoder.encode("password123"));
        userRepo.save(u);

        // Server must NOT reveal that the email already exists; the response
        // looks identical to a fresh signup. This kills email enumeration.
        mvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "name", "tester",
                                "email", "dup@example.com",
                                "password", "password123"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OK"));

        // And the existing user record must not have been overwritten.
        AppUser still = userRepo.findByEmail("dup@example.com").orElseThrow();
        assert "existing".equals(still.getName()) : "duplicate signup must not overwrite existing user";
    }

    @Test
    @DisplayName("POST /auth/signup — invalid email returns 400")
    void signupInvalidEmail() throws Exception {
        mvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "name", "tester",
                                "email", "not-an-email",
                                "password", "password123"
                        ))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /auth/signup — short password returns 400")
    void signupShortPassword() throws Exception {
        mvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "name", "tester",
                                "email", "test@example.com",
                                "password", "short"
                        ))))
                .andExpect(status().isBadRequest());
    }

    // ─── Login ───

    @Test
    @DisplayName("POST /auth/login — success returns access token")
    void loginSuccess() throws Exception {
        AppUser u = new AppUser();
        u.setEmail("login@example.com");
        u.setName("tester");
        u.setRole("USER");
        u.setPasswordHash(encoder.encode("password123"));
        userRepo.save(u);

        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "email", "login@example.com",
                                "password", "password123"
                        ))))
                .andExpect(status().isOk())
                // Access token is now delivered via HttpOnly cookie, not in body.
                .andExpect(header().exists("Set-Cookie"))
                .andExpect(jsonPath("$.email").value("login@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("POST /auth/login — wrong password returns 401")
    void loginWrongPassword() throws Exception {
        AppUser u = new AppUser();
        u.setEmail("wrong@example.com");
        u.setName("tester");
        u.setRole("USER");
        u.setPasswordHash(encoder.encode("password123"));
        userRepo.save(u);

        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "email", "wrong@example.com",
                                "password", "wrongpassword"
                        ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    @DisplayName("POST /auth/login — nonexistent email returns 401")
    void loginNonexistentEmail() throws Exception {
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of(
                                "email", "nobody@example.com",
                                "password", "password123"
                        ))))
                .andExpect(status().isUnauthorized());
    }

    // ─── /auth/me ───

    @Test
    @DisplayName("GET /auth/me — unauthenticated returns 401")
    void meUnauthenticated() throws Exception {
        mvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    // ─── Logout ───

    @Test
    @DisplayName("POST /auth/logout — returns OK")
    void logoutSuccess() throws Exception {
        // /auth/logout is a cookie-bearing state-changing endpoint — CSRF
        // protection applies. spring-security-test's csrf() postprocessor
        // injects a valid token for the test.
        mvc.perform(post("/auth/logout").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("OK"));
    }
}
