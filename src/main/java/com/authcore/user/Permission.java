package com.authcore.user;

import jakarta.persistence.*;

import java.util.UUID;

/**
 * A single capability, named the way code checks it: {@code payments:write}.
 *
 * <p>Deliberately unprefixed. Roles carry Spring's {@code ROLE_} convention so
 * {@code hasRole()} works; permissions stay bare so {@code hasAuthority('payments:write')}
 * reads as the thing it actually guards.
 */
@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    protected Permission() {
    }

    public Permission(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public UUID getId() { return id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
