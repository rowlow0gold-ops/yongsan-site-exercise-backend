package com.example.demo.board.repository;

import com.example.demo.board.entity.BoardPost;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface BoardPostRepository extends JpaRepository<BoardPost, Long> {

    @Query("""
      select p from BoardPost p
      where p.boardKey = :boardKey
        and (:q is null or :q = '' 
             or lower(p.title) like lower(concat('%', :q, '%'))
             or lower(p.content) like lower(concat('%', :q, '%')))
    """)
    Page<BoardPost> findPage(@Param("boardKey") String boardKey,
                             @Param("q") String q,
                             Pageable pageable);

    Optional<BoardPost> findByIdAndBoardKey(Long id, String boardKey);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
  update BoardPost p
  set p.views = p.views + 1
  where p.boardKey = :boardKey and p.id = :id
""")
    int incrementViews(@Param("boardKey") String boardKey, @Param("id") Long id);

}
