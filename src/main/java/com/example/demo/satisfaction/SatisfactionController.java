package com.example.demo.satisfaction;

import com.example.demo.auth.AuthContext;
import com.example.demo.auth.ClientIpResolver;
import com.example.demo.auth.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import com.example.demo.captcha.TurnstileVerifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/satisfaction")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Satisfaction", description = "만족도 조사 API")
public class SatisfactionController {

    private final PageSatisfactionRepository repository;
    private final ClientIpResolver clientIpResolver;
    private final TurnstileVerifier turnstile;
    private final RateLimitService rateLimit;

    @PostMapping
    public ResponseEntity<?> submit(
            @Valid @RequestBody SatisfactionRequest req,
            HttpServletRequest httpReq
    ) {
        if (!turnstile.verify(req.getCfTurnstileToken(), clientIpResolver.resolve(httpReq))) {
            throw new IllegalArgumentException("Captcha verification failed. Please reload and try again.");
        }
        String ip = clientIpResolver.resolve(httpReq);

        // 20 ratings / 10 minutes / IP — generous for legitimate use, kills bots.
        if (!rateLimit.tryAcquire("satisfaction:" + ip, 20, Duration.ofMinutes(10))) {
            return ResponseEntity.status(429)
                    .header("Retry-After", "600")
                    .body(new Msg("Too many submissions."));
        }

        PageSatisfaction entity = new PageSatisfaction();
        entity.setPagePath(req.getPagePath());
        entity.setRating(req.getRating());
        entity.setFeedback(req.getFeedback() != null ? req.getFeedback().trim() : null);
        entity.setIpAddress(ip);
        entity.setUserId(AuthContext.userIdOrNull());

        repository.save(entity);

        return ResponseEntity.ok(new Msg("OK"));
    }

    public record Msg(String message) {}
}
