package com.example.demo.board.controller;

import com.example.demo.board.dto.*;
import com.example.demo.board.service.BoardPostService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/boards/{boardKey}/posts")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Board", description = "게시판 API (목록/상세/작성/수정/삭제)")
public class BoardPostController {

    private final BoardPostService service;

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
            @PathVariable Long id,
            @RequestParam(required = false) String password
    ) {
        try {
            return ResponseEntity.ok(service.detail(boardKey, id, password));
        } catch (AccessDeniedException e) {
            boolean guestPrivate = "GUEST_PRIVATE".equals(e.getMessage());
            return ResponseEntity.status(403).body(new PrivateErrorResponse(
                    guestPrivate ? "비밀번호를 입력하면 열람할 수 있습니다." : "작성자 본인 또는 관리자만 열람할 수 있습니다.",
                    guestPrivate
            ));
        }
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
