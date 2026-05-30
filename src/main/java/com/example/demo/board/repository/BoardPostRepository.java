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

    /**
     * Account-deletion (탈퇴) helper. Detaches a withdrawing user from their
     * posts: keeps the content (community value) but drops attribution.
     * The author display string becomes "탈퇴한 회원", FK to app_users is
     * nulled, and the post can no longer be edited/deleted by anyone.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
  update BoardPost p
  set p.authorUserId = null,
      p.author       = '탈퇴한 회원'
  where p.authorUserId = :userId
""")
    int anonymizePostsByUser(@Param("userId") Long userId);
}
