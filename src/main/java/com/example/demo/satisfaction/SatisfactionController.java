package com.example.demo.satisfaction;

import com.example.demo.auth.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/satisfaction")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Satisfaction", description = "만족도 조사 API")
public class SatisfactionController {

    private final PageSatisfactionRepository repository;

    @PostMapping
    public ResponseEntity<?> submit(
            @Valid @RequestBody SatisfactionRequest req,
            HttpServletRequest httpReq
    ) {
        PageSatisfaction entity = new PageSatisfaction();
        entity.setPagePath(req.getPagePath());
        entity.setRating(req.getRating());
        entity.setFeedback(req.getFeedback() != null ? req.getFeedback().trim() : null);
        entity.setIpAddress(httpReq.getRemoteAddr());
        entity.setUserId(AuthContext.userIdOrNull());

        repository.save(entity);

        return ResponseEntity.ok(new Msg("OK"));
    }

    public record Msg(String message) {}
}
