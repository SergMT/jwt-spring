package com.programandoenjava.jwt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

  @Query(value = """
    SELECT t FROM Token t 
    JOIN t.user u 
    WHERE u.id = :id AND (t.isExpired = false OR t.isRevoked = false)
    """)
  List<Token> findAllValidTokenByUser(@Param("id") Integer id);

  Optional<Token> findByToken(String token);
}
