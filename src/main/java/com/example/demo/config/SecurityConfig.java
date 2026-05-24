package com.example.demo.config;

import com.example.demo.auth.OAuth2SuccessHandler;
import com.example.demo.auth.jwt.JwtAuthFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.PermissionsPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        // CSRF: double-submit cookie pattern. Spring writes a non-HttpOnly
        // XSRF-TOKEN cookie that JS can read; the SPA's axios sends it back
        // as the X-XSRF-TOKEN header on state-changing requests. Endpoints
        // that legitimately can't have a pre-existing CSRF context (initial
        // login, signup, OAuth callbacks, code exchange) are ignored.
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null); // opt out of BREACH protection so SPAs can copy cookie verbatim

        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler)
                        .ignoringRequestMatchers(
                                "/auth/login",
                                "/auth/signup",
                                "/auth/exchange",
                                "/oauth2/**",
                                "/login/oauth2/**"
                        )
                )
                .cors(cors -> cors.configurationSource(req -> {
                    CorsConfiguration c = new CorsConfiguration();
                    c.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
                    c.setAllowedHeaders(List.of("*"));
                    c.setAllowCredentials(true);
                    c.setAllowedOrigins(List.of(
                            "http://localhost:5173",
                            "https://minhojan-world.site",
                            "https://www.minhojan-world.site",
                            "https://test.minhojan-world.site",
                            "https://yongsan.minhojan-world.site",
                            "https://test-yongsan.minhojan-world.site"
                    ));
                    return c;
                }))
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2SuccessHandler)
                )
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // --- Auth surface (no JWT needed to start a session)
                        .requestMatchers("/auth/login", "/auth/refresh", "/auth/logout", "/auth/signup", "/auth/exchange").permitAll()
                        .requestMatchers("/auth/me").authenticated()
                        // --- Boards
                        .requestMatchers(HttpMethod.GET, "/api/boards/board2/posts").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/boards/board2/posts/**").authenticated()
                        .requestMatchers("/api/boards/board2/**").authenticated()
                        .requestMatchers("/api/boards/**").permitAll()
                        // --- Satisfaction widget (guests submit anonymously)
                        .requestMatchers(HttpMethod.POST, "/api/satisfaction").permitAll()
                        // --- OAuth callback paths
                        .requestMatchers("/login/oauth2/**", "/oauth2/**").permitAll()
                        // --- Health is public; the rest of /actuator (metrics, prometheus, env, etc.) is ADMIN-only
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers("/actuator/**").hasRole("ADMIN")
                        // --- API docs: ADMIN only (was permitAll; exposed every endpoint + DTO)
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/api-docs/**", "/v3/api-docs/**").hasRole("ADMIN")
                        // --- Public health probe (separate from /actuator/health for app-level checks)
                        .requestMatchers(HttpMethod.GET, "/api/health").permitAll()
                        // --- Spring's error dispatcher must be reachable so error responses render
                        .requestMatchers("/error").permitAll()
                        // --- Default-deny: anything not explicitly permitted requires auth
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // Materialise the CSRF token on every response so the SPA can
                // read XSRF-TOKEN from any request, not just state-changing ones.
                .addFilterAfter(new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                            throws ServletException, IOException {
                        CsrfToken token = (CsrfToken) req.getAttribute(CsrfToken.class.getName());
                        if (token != null) token.getToken();
                        chain.doFilter(req, res);
                    }
                }, CsrfFilter.class);

        http.headers(h -> h
                .frameOptions(f -> f.deny())
                .contentTypeOptions(c -> {})
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                .addHeaderWriter(new PermissionsPolicyHeaderWriter("geolocation=(), microphone=(), camera=()"))
                .addHeaderWriter(new ContentSecurityPolicyHeaderWriter(
                        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
                ))
        );

        return http.build();
    }
}