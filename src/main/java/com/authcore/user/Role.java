package com.authcore.user;

import com.authcore.tenant.Tenant;
import jakarta.persistence.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * A named bundle of {@link Permission}s. Stored with the {@code ROLE_} prefix so
 * Spring's {@code hasRole()} works without translation.
 */
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Unique per tenant: Acme's ROLE_ADMIN is not Globex's ROLE_ADMIN.
    @Column(nullable = false, length = 50)
    private String name;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(length = 255)
    private String description;

    // EAGER because every login resolves the full authority set; a lazy load here
    // would just be a guaranteed second query outside the session.
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<Permission> permissions = new HashSet<>();

    protected Role() {
    }

    public Role(String name, String description, Tenant tenant) {
        this.name = name;
        this.description = description;
        this.tenant = tenant;
    }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public UUID getId() { return id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Set<Permission> getPermissions() { return permissions; }
}
