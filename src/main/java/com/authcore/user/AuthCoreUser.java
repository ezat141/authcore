package com.authcore.user;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class AuthCoreUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public UUID getId() { return id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Instant getCreatedAt() { return createdAt; }

    public Set<Role> getRoles() { return roles; }

    /**
     * Flattens roles and their permissions into the authority strings Spring checks:
     * {@code ROLE_USER}, {@code payments:read}, …
     */
    public Set<String> toAuthorityNames() {
        Set<String> authorities = new HashSet<>();
        for (Role role : roles) {
            authorities.add(role.getName());
            role.getPermissions().forEach(permission -> authorities.add(permission.getName()));
        }
        return authorities;
    }

    public Set<String> roleNames() {
        return roles.stream()
                .map(Role::getName)
                .map(name -> name.startsWith("ROLE_") ? name.substring("ROLE_".length()) : name)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    }

    public Set<String> permissionNames() {
        Set<String> permissions = new HashSet<>();
        roles.forEach(role -> role.getPermissions().forEach(p -> permissions.add(p.getName())));
        return permissions;
    }
}
