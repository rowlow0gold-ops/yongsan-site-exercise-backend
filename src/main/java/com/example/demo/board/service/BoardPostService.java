package com.example.demo.board.service;

import com.example.demo.auth.AuthContext;
import com.example.demo.board.dto.*;
import com.example.demo.board.entity.BoardPost;
import com.example.demo.board.repository.BoardPostRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import org.springframework.security.access.AccessDeniedException;

import com.example.demo.board.BoardKeys;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.CacheEvict;

@Service
@RequiredArgsConstructor
public class BoardPostService {

    private final BoardPostRepository repository;
    private final PasswordEncoder passwordEncoder;

    private void validateBoardKey(String boardKey) {
        if (!List.of("board1", "board2").contains(boardKey)) {
            throw new EntityNotFoundException("board not found");
        }
    }

    @Transactional(readOnly = true)
    public BoardPostListResponse list(String boardKey, int page, int size, String q) {
        validateBoardKey(boardKey);
        int safePage = Math.max(page, 1);
        int safeSize = Math.min(Math.max(size, 1), 50);
        Pageable pageable = PageRequest.of(safePage - 1, safeSize, Sort.by(Sort.Direction.DESC, "id"));
        String safeQ = (q == null) ? null : q.trim();
        if (safeQ != null && safeQ.length() > 100) {
            throw new IllegalArgumentException("q is too long");
        }
        Page<BoardPost> result = repository.findPage(boardKey, safeQ, pageable);

        Long me = AuthContext.userIdOrNull();
        String myRole = AuthContext.roleOrNull();
        boolean isAdmin = "ADMIN".equals(myRole);

        List<BoardPostListResponse.Item> items = result.getContent().stream()
                .map(p -> {
                    boolean isPrivate = "PRIVATE".equals(p.getVisibility());
                    boolean isOwner = me != null && me.equals(p.getAuthorUserId());
                    boolean canSee = !isPrivate || isOwner || isAdmin;

                    return new BoardPostListResponse.Item(
                            p.getId(),
                            canSee ? p.getTitle() : "비공개글입니다",
                            canSee ? p.getAuthor() : "비공개",
                            p.getCreatedAt(), p.getUpdatedAt(), p.getViews(),
                            p.getVisibility(),
                            canSee ? p.getAuthorUserId() : null,
                            p.getAuthorUserId() == null
                    );
                })
                .toList();

        return new BoardPostListResponse(items, result.getTotalElements());
    }

    @Transactional
    public BoardPostDetailResponse detail(String boardKey, Long id, String password) {
        validateBoardKey(boardKey);
        int updated = repository.incrementViews(boardKey, id);
        if (updated == 0) throw new EntityNotFoundException("post not found");

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        // PRIVATE: only author or ADMIN can view
        if ("PRIVATE".equals(p.getVisibility())) {
            Long me = AuthContext.userIdOrNull();
            String myRole = AuthContext.roleOrNull();
            boolean isAdmin = "ADMIN".equals(myRole);
            boolean isAuthor = me != null && me.equals(p.getAuthorUserId());

            // Guest private post: allow access with correct password
            boolean isGuestPost = p.getAuthorUserId() == null;
            boolean passwordOk = isGuestPost && password != null
                    && p.getPasswordHash() != null
                    && passwordEncoder.matches(password, p.getPasswordHash());

            if (!isAdmin && !isAuthor && !passwordOk) {
                throw new AccessDeniedException(isGuestPost ? "GUEST_PRIVATE" : "MEMBER_PRIVATE");
            }
        }

        return new BoardPostDetailResponse(
                p.getId(), p.getBoardKey(), p.getTitle(), p.getAuthor(), p.getContent(),
                p.getCreatedAt(), p.getUpdatedAt(), p.getViews(), p.getAuthorUserId(),
                p.getVisibility()
        );
    }

    @Transactional
    public Long create(String boardKey, BoardPostWriteRequest req) {
        validateBoardKey(boardKey);
        Long userId = AuthContext.userIdOrNull();

        if ("board2".equals(boardKey)) {
            if (userId == null) throw new AccessDeniedException("Login required.");
        }

        String title = req.getTitle().trim();
        String author = req.getAuthor() == null ? null : req.getAuthor().trim();
        String content = req.getContent().trim();
        String visibility = req.getVisibility() != null ? req.getVisibility() : "PUBLIC";

        BoardPost post = new BoardPost(boardKey, title, author, content);
        post.setVisibility(visibility);

        if (userId != null) {
            post.setAuthorUserId(userId);
            post.setPasswordHash(null);
        } else {
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
        validateBoardKey(boardKey);
        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        String myRole = AuthContext.roleOrNull();
        boolean isAdmin = "ADMIN".equals(myRole);

        if (!isAdmin) {
            if ("board2".equals(boardKey)) {
                Long me = AuthContext.userIdOrNull();
                if (me == null) throw new AccessDeniedException("Login required.");
                if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
            }

            if (BoardKeys.PRAISE.equals(boardKey)) {
                if (p.getAuthorUserId() != null) {
                    Long me = AuthContext.userIdOrNull();
                    if (me == null) throw new AccessDeniedException("Login required.");
                    if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
                } else {
                    if (req.getPassword() == null) throw new IllegalArgumentException("Password is required.");
                    if (p.getPasswordHash() == null || !passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                        throw new AccessDeniedException("Wrong password.");
                    }
                }
            }
        }

        String visibility = req.getVisibility() != null ? req.getVisibility() : p.getVisibility();
        p.update(req.getTitle().trim(),
                req.getAuthor() == null ? null : req.getAuthor().trim(),
                req.getContent().trim(),
                visibility);
    }

    @Transactional
    public void delete(String boardKey, Long id, BoardPostWriteRequest req) {
        validateBoardKey(boardKey);
        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        String myRole = AuthContext.roleOrNull();
        boolean isAdmin = "ADMIN".equals(myRole);

        if (!isAdmin) {
            if ("board2".equals(boardKey)) {
                Long me = AuthContext.userIdOrNull();
                if (me == null) throw new AccessDeniedException("Login required.");
                if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
            }

            if (BoardKeys.PRAISE.equals(boardKey)) {
                if (p.getAuthorUserId() != null) {
                    Long me = AuthContext.userIdOrNull();
                    if (me == null) throw new AccessDeniedException("Login required.");
                    if (!me.equals(p.getAuthorUserId())) throw new AccessDeniedException("Not the owner.");
                } else {
                    if (req == null || req.getPassword() == null) throw new IllegalArgumentException("Password is required.");
                    if (p.getPasswordHash() == null || !passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                        throw new AccessDeniedException("Wrong password.");
                    }
                }
            }
        }

        repository.delete(p);
    }
}
