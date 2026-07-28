package com.authcore.keys;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    Optional<SigningKey> findByStatus(SigningKey.Status status);

    List<SigningKey> findAllByStatusOrderByCreatedAtDesc(SigningKey.Status status);

    /** Retired keys stop mattering once every token they signed has expired. */
    List<SigningKey> findAllByStatusAndRetiredAtBefore(SigningKey.Status status, Instant cutoff);
}
