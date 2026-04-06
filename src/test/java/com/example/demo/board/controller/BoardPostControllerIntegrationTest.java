package com.example.demo.board.controller;

import com.example.demo.auth.entity.AppUser;
import com.example.demo.auth.jwt.JwtUtil;
import com.example.demo.auth.repository.AppUserRepository;
import com.example.demo.board.entity.BoardPost;
import com.example.demo.board.repository.BoardPostRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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

import static org.hamcrest.Matchers.*;
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
        "spring.data.redis.port=6379"
})
class BoardPostControllerIntegrationTest {

    MockMvc mvc;
    final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    @Autowired BoardPostRepository postRepo;
    @Autowired AppUserRepository userRepo;
    @Autowired JwtUtil jwt;
    @Autowired PasswordEncoder encoder;
    @Autowired WebApplicationContext wac;

    private AppUser testUser;
    private String accessToken;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(springSecurity())
                .build();
        postRepo.deleteAll();
        userRepo.deleteAll();

        testUser = new AppUser();
        testUser.setEmail("boarduser@example.com");
        testUser.setName("Board Tester");
        testUser.setRole("USER");
        testUser.setPasswordHash(encoder.encode("password123"));
        testUser = userRepo.save(testUser);

        accessToken = jwt.createAccessToken(testUser.getId(), testUser.getRole());
    }

    private BoardPost createPost(String boardKey, String title, Long authorUserId) {
        BoardPost p = new BoardPost(boardKey, title, "author", "content body");
        p.setAuthorUserId(authorUserId);
        p.setVisibility("PUBLIC");
        return postRepo.save(p);
    }

    // ─── Board1 (Praise Board) ───

    @Nested
    @DisplayName("Board1 - Praise Board")
    class Board1Tests {

        @Test
        @DisplayName("GET /api/boards/board1/posts — list posts")
        void listBoard1Posts() throws Exception {
            createPost("board1", "Praise Post 1", testUser.getId());
            createPost("board1", "Praise Post 2", testUser.getId());

            mvc.perform(get("/api/boards/board1/posts"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.items", hasSize(2)))
                    .andExpect(jsonPath("$.total").value(2));
        }

        @Test
        @DisplayName("POST /api/boards/board1/posts — guest post with password")
        void createGuestPost() throws Exception {
            mvc.perform(post("/api/boards/board1/posts")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(Map.of(
                                    "title", "Guest Praise",
                                    "author", "guest",
                                    "content", "Great work!",
                                    "password", "secret123"
                            ))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").isNumber());
        }

        @Test
        @DisplayName("POST /api/boards/board1/posts — guest post without password fails")
        void createGuestPostNoPassword() throws Exception {
            mvc.perform(post("/api/boards/board1/posts")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(Map.of(
                                    "title", "No Password",
                                    "author", "guest",
                                    "content", "Should fail"
                            ))))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("POST /api/boards/board1/posts — member post (no password needed)")
        void createMemberPost() throws Exception {
            mvc.perform(post("/api/boards/board1/posts")
                            .header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(Map.of(
                                    "title", "Member Praise",
                                    "author", "member",
                                    "content", "Member post!"
                            ))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").isNumber());
        }
    }

    // ─── Board2 (requires login) ───

    @Nested
    @DisplayName("Board2 - Community Talk (login required)")
    class Board2Tests {

        @Test
        @DisplayName("GET /api/boards/board2/posts — list is public")
        void listBoard2Posts() throws Exception {
            createPost("board2", "Talk Post", testUser.getId());

            mvc.perform(get("/api/boards/board2/posts"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.items", hasSize(1)));
        }

        @Test
        @DisplayName("POST /api/boards/board2/posts — unauthenticated fails")
        void createWithoutLoginFails() throws Exception {
            mvc.perform(post("/api/boards/board2/posts")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(Map.of(
                                    "title", "Anon post",
                                    "author", "anon",
                                    "content", "Should fail"
                            ))))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("POST /api/boards/board2/posts — authenticated succeeds")
        void createWithLoginSucceeds() throws Exception {
            mvc.perform(post("/api/boards/board2/posts")
                            .header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(mapper.writeValueAsString(Map.of(
                                    "title", "My Talk",
                                    "author", "tester",
                                    "content", "Hello community!"
                            ))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").isNumber());
        }

        @Test
        @DisplayName("DELETE /api/boards/board2/posts/{id} — owner can delete")
        void ownerCanDelete() throws Exception {
            BoardPost p = createPost("board2", "To Delete", testUser.getId());

            mvc.perform(delete("/api/boards/board2/posts/" + p.getId())
                            .header("Authorization", "Bearer " + accessToken)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk());
        }
    }

    // ─── Invalid Board ───

    @Test
    @DisplayName("GET /api/boards/invalid/posts — invalid board key returns 404")
    void invalidBoardKey() throws Exception {
        mvc.perform(get("/api/boards/invalid/posts"))
                .andExpect(status().isNotFound());
    }

    // ─── Search ───

    @Test
    @DisplayName("GET /api/boards/board1/posts?q=keyword — search works")
    void searchPosts() throws Exception {
        createPost("board1", "Hello World", testUser.getId());
        createPost("board1", "Goodbye World", testUser.getId());

        mvc.perform(get("/api/boards/board1/posts").param("q", "Hello"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(1)))
                .andExpect(jsonPath("$.items[0].title").value("Hello World"));
    }

    // ─── Pagination ───

    @Test
    @DisplayName("GET /api/boards/board1/posts — pagination works")
    void pagination() throws Exception {
        for (int i = 0; i < 25; i++) {
            createPost("board1", "Post " + i, testUser.getId());
        }

        mvc.perform(get("/api/boards/board1/posts")
                        .param("page", "1")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items", hasSize(10)))
                .andExpect(jsonPath("$.total").value(25));
    }

    // ─── Private Posts ───

    @Test
    @DisplayName("GET /api/boards/board1/posts/{id} — private post hidden from others")
    void privatePostHiddenFromOthers() throws Exception {
        BoardPost p = new BoardPost("board1", "Secret", "author", "hidden content");
        p.setAuthorUserId(testUser.getId());
        p.setVisibility("PRIVATE");
        p = postRepo.save(p);

        // Unauthenticated user gets 403
        mvc.perform(get("/api/boards/board1/posts/" + p.getId()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /api/boards/board1/posts/{id} — owner can view own private post")
    void ownerCanViewPrivatePost() throws Exception {
        BoardPost p = new BoardPost("board1", "My Secret", "author", "my hidden content");
        p.setAuthorUserId(testUser.getId());
        p.setVisibility("PRIVATE");
        p = postRepo.save(p);

        mvc.perform(get("/api/boards/board1/posts/" + p.getId())
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("My Secret"));
    }
}
