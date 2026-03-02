package com.example.demo.board.service;

import com.example.demo.board.dto.*;
import com.example.demo.board.entity.BoardPost;
import com.example.demo.board.repository.BoardPostRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.demo.board.BoardKeys;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class BoardPostService {

    private final BoardPostRepository repository;
    private final PasswordEncoder passwordEncoder;

    private Long currentUserIdOrNull() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;

        Object principal = auth.getPrincipal();
        if (principal == null) return null;

        try {
            return Long.valueOf(String.valueOf(principal));
        } catch (Exception e) {
            return null;
        }
    }

    @Transactional(readOnly = true)
    public BoardPostListResponse list(String boardKey, int page, int size, String q) {
        Pageable pageable = PageRequest.of(Math.max(page - 1, 0), size, Sort.by(Sort.Direction.DESC, "id"));
        Page<BoardPost> result = repository.findPage(boardKey, q, pageable);

        List<BoardPostListResponse.Item> items = result.getContent().stream()
                .map(p -> new BoardPostListResponse.Item(
                        p.getId(), p.getTitle(), p.getAuthor(), p.getCreatedAt(), p.getUpdatedAt(), p.getViews()
                ))
                .toList();

        return new BoardPostListResponse(items, result.getTotalElements());
    }

    @Transactional
    public BoardPostDetailResponse detail(String boardKey, Long id) {

        int updated = repository.incrementViews(boardKey, id);

        if (updated == 0) throw new EntityNotFoundException("post not found");

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        return new BoardPostDetailResponse(
                p.getId(), p.getBoardKey(), p.getTitle(), p.getAuthor(), p.getContent(),
                p.getCreatedAt(), p.getUpdatedAt(), p.getViews(), p.getAuthorUserId()
        );
    }

    @Transactional
    public Long create(String boardKey, BoardPostWriteRequest req) {

        Long userId = currentUserIdOrNull();

        // ✅ board2 must be logged in
        if ("board2".equals(boardKey)) {
            if (userId == null) throw new AccessDeniedException("Login required.");
        }

        BoardPost post = new BoardPost(boardKey, req.getTitle(), req.getAuthor(), req.getContent());

        // ✅ if logged in, always save authorUserId (for board2 and also board1 member posts)
        if (userId != null) {
            post.setAuthorUserId(userId);
            post.setPasswordHash(null);
        } else {
            // guest allowed only for board1
            if (BoardKeys.PRAISE.equals(boardKey)) {
                if (req.getPassword() == null || req.getPassword().length() < 6) {
                    throw new IllegalArgumentException("Password must be at least 6 characters.");
                }
                post.setPasswordHash(passwordEncoder.encode(req.getPassword()));
                post.setAuthorUserId(null);
            } else {
                throw new AccessDeniedException("Login required.");
            }
        }

        return repository.save(post).getId();
    }

    @Transactional
    public void update(String boardKey, Long id, BoardPostWriteRequest req) {

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        if (BoardKeys.PRAISE.equals(boardKey)) {
            if (p.getAuthorUserId() != null) {
                // ✅ member post → JWT + owner check
                Long me = currentUserIdOrNull();
                if (me == null) throw new AccessDeniedException("Login required.");
                if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
            } else {
                // ✅ guest post → password check
                if (req.getPassword() == null) throw new IllegalArgumentException("Password is required.");
                if (p.getPasswordHash() == null || !passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                    throw new IllegalArgumentException("Wrong password.");
                }
            }
        }

        p.update(req.getTitle(), req.getAuthor(), req.getContent());
    }

    @Transactional
    public void delete(String boardKey, Long id, BoardPostWriteRequest req) {

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        if (BoardKeys.PRAISE.equals(boardKey)) {
            if (p.getAuthorUserId() != null) {
                Long me = currentUserIdOrNull();
                if (me == null) throw new AccessDeniedException("Login required.");
                if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
            } else {
                if (req == null || req.getPassword() == null) throw new IllegalArgumentException("Password is required.");
                if (p.getPasswordHash() == null || !passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                    throw new IllegalArgumentException("Wrong password.");
                }
            }
        }

        repository.delete(p);
    }
}
