package com.example.demo.auth;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.repository.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.jwt.secret=testsecrettestsecrettestsecrettestsecret",
        "app.jwt.accessTtlSeconds=900",
        "app.jwt.refreshTtlSeconds=1209600",
        "app.jwt.refreshCookieName=refresh_token",
        "app.oauth2.redirect-uri=http://localhost:5173",
        "spring.security.oauth2.client.registration.google.client-id=test-client-id",
        "spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
        "spring.security.oauth2.client.registration.google.scope=email,profile"
})
class AuthControllerTest {

    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        users.deleteAll();
    }

    @Test
    void saveAndFindUser() {
        AppUser user = new AppUser();
        user.setEmail("test@test.com");
        user.setName("Test User");
        user.setRole("USER");
        user.setPasswordHash(encoder.encode("password123"));
        users.save(user);

        AppUser found = users.findByEmail("test@test.com").orElse(null);
        assertThat(found).isNotNull();
        assertThat(found.getEmail()).isEqualTo("test@test.com");
    }

    @Test
    void passwordEncoderWorks() {
        String raw = "password123";
        String encoded = encoder.encode(raw);
        assertThat(encoder.matches(raw, encoded)).isTrue();
        assertThat(encoder.matches("wrong", encoded)).isFalse();
    }

    @Test
    void duplicateEmailNotSaved() {
        AppUser u1 = new AppUser();
        u1.setEmail("dup@test.com");
        u1.setName("User 1");
        u1.setRole("USER");
        u1.setPasswordHash(encoder.encode("pass"));
        users.save(u1);

        assertThat(users.findByEmail("dup@test.com")).isPresent();
        assertThat(users.count()).isEqualTo(1);
    }
}