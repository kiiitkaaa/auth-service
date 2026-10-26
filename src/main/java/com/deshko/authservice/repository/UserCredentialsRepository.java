package com.deshko.authservice.repository;

import com.deshko.authservice.entity.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long> {
    Optional<UserCredentials> findByLogin(String login);
    Optional<UserCredentials> findByUserId(Long userId);
    boolean existsByLogin(String login);
    boolean existsByUserId(Long userId);
}
