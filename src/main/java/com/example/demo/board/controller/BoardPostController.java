package com.example.demo.board.controller;

import com.example.demo.board.dto.*;
import com.example.demo.board.service.BoardPostService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/boards/{boardKey}/posts")
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
    public BoardPostDetailResponse detail(@PathVariable String boardKey, @PathVariable Long id) {
        return service.detail(boardKey, id);
    }

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
