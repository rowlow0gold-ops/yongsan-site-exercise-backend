package com.example.demo.board.controller;

import com.example.demo.auth.ClientIpResolver;
import com.example.demo.auth.RateLimitService;
import com.example.demo.board.dto.*;
import com.example.demo.board.service.BoardPostService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/boards/{boardKey}/posts")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Board", description = "게시판 API (목록/상세/작성/수정/삭제)")
public class BoardPostController {

    private final BoardPostService service;
    private final ClientIpResolver clientIpResolver;
    private final RateLimitService rateLimit;

    @GetMapping
    public BoardPostListResponse list(
            @PathVariable String boardKey,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String q
    ) {
        return service.list(boardKey, page, size, q);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> detail(
            @PathVariable String boardKey,
            @PathVariable Long id
    ) {
        // SECURITY: passwords used to be accepted here as ?password=... — that
        // leaked into nginx/Cloudflare access logs, browser history, and any
        // outbound Referer header. The password path now lives on POST /unlock
        // below, with the password in the JSON body and a per-(post, ip) rate
        // limit. The plain GET only returns public posts or the author's own.
        try {
            return ResponseEntity.ok(service.detail(boardKey, id, null));
        } catch (AccessDeniedException e) {
            boolean guestPrivate = "GUEST_PRIVATE".equals(e.getMessage());
            return ResponseEntity.status(403).body(new PrivateErrorResponse(
                    guestPrivate ? "비밀번호를 입력하면 열람할 수 있습니다." : "작성자 본인 또는 관리자만 열람할 수 있습니다.",
                    guestPrivate
            ));
        }
    }

    /**
     * Unlock a guest-private post by supplying its password in the request body.
     * Rate-limited per (post, IP) to make online brute force impractical.
     */
    @PostMapping("/{id}/unlock")
    public ResponseEntity<?> unlock(
            @PathVariable String boardKey,
            @PathVariable Long id,
            @Valid @RequestBody UnlockRequest body,
            HttpServletRequest httpReq
    ) {
        String ip = clientIpResolver.resolve(httpReq);
        // 10 attempts / 10 minutes / (post, ip). A 10-char password gives the
        // attacker ≈ 10^-19 success per try at this cap; combined with the
        // 10-char minimum below this makes brute force infeasible.
        if (!rateLimit.tryAcquire("unlock:" + boardKey + ":" + id + ":" + ip, 10, Duration.ofMinutes(10))) {
            return ResponseEntity.status(429)
                    .header("Retry-After", "600")
                    .body(new PrivateErrorResponse("Too many attempts. Try again later.", true));
        }
        try {
            return ResponseEntity.ok(service.detail(boardKey, id, body.getPassword()));
        } catch (AccessDeniedException e) {
            boolean guestPrivate = "GUEST_PRIVATE".equals(e.getMessage());
            return ResponseEntity.status(403).body(new PrivateErrorResponse(
                    guestPrivate ? "비밀번호가 올바르지 않습니다." : "작성자 본인 또는 관리자만 열람할 수 있습니다.",
                    guestPrivate
            ));
        }
    }

    @Data
    public static class UnlockRequest {
        @NotBlank @Size(min = 6, max = 100)
        private String password;
    }

    public record PrivateErrorResponse(String message, boolean guestPost) {}

    @PostMapping
    public IdResponse create(@PathVariable String boardKey, @Valid @RequestBody BoardPostWriteRequest req) {
        Long id = service.create(boardKey, req);
        return new IdResponse(id);
    }

    @PutMapping("/{id}")
    public void update(@PathVariable String boardKey, @PathVariable Long id, @Valid @RequestBody BoardPostWriteRequest req) {
        service.update(boardKey, id, req);
    }

    @DeleteMapping("/{id}")
    public void delete(
            @PathVariable String boardKey,
            @PathVariable Long id,
            @RequestBody(required = false) BoardPostWriteRequest req
    ) {
        service.delete(boardKey, id, req);
    }

    public record IdResponse(Long id) {}
}
