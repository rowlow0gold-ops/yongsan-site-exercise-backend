package com.example.demo.board.service;

import com.example.demo.board.dto.*;
import com.example.demo.board.entity.BoardPost;
import com.example.demo.board.repository.BoardPostRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import com.example.demo.board.BoardKeys;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class BoardPostService {

    private final BoardPostRepository repository;
    private final PasswordEncoder passwordEncoder;

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
                p.getCreatedAt(), p.getUpdatedAt(), p.getViews()
        );
    }


    @Transactional
    public Long create(String boardKey, BoardPostWriteRequest req) {

        BoardPost post = new BoardPost(boardKey, req.getTitle(), req.getAuthor(), req.getContent());

        // if praise board → require password
        if (BoardKeys.PRAISE.equals(boardKey)) {

            if (req.getPassword() == null || req.getPassword().length() < 6) {
                throw new IllegalArgumentException("Password must be at least 6 characters.");
            }

            post.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        }

        BoardPost saved = repository.save(post);
        return saved.getId();
    }

    @Transactional
    public void update(String boardKey, Long id, BoardPostWriteRequest req) {

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        if (BoardKeys.PRAISE.equals(boardKey)) {

            if (req.getPassword() == null) {
                throw new IllegalArgumentException("Password is required.");
            }

            if (!passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                throw new IllegalArgumentException("Wrong password.");
            }
        }

        p.update(req.getTitle(), req.getAuthor(), req.getContent());
    }

    @Transactional
    public void delete(String boardKey, Long id, BoardPostWriteRequest req) {

        BoardPost p = repository.findByIdAndBoardKey(id, boardKey)
                .orElseThrow(() -> new EntityNotFoundException("post not found"));

        if (BoardKeys.PRAISE.equals(boardKey)) {

            if (req.getPassword() == null) {
                throw new IllegalArgumentException("Password is required.");
            }

            if (!passwordEncoder.matches(req.getPassword(), p.getPasswordHash())) {
                throw new IllegalArgumentException("Wrong password.");
            }
        }

        repository.delete(p);
    }
}
