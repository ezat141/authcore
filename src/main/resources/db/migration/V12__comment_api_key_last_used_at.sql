-- Records what last_used_at now means, since M3 changed it.
--
-- It is updated on every validation at the source, including introspection calls from
-- GateKeeper. Because the gateway caches an introspection answer for its configured TTL,
-- a continuously-used key is introspected only once per TTL. Read this as "last validated
-- at the source, accurate to within that TTL", not "last used".
--
-- A separate migration rather than an edit to V7: Flyway checksums the whole file,
-- comments included, so editing an applied migration breaks validation on boot.
COMMENT ON COLUMN api_keys.last_used_at IS
    'Last validated at the source. Gateway caching means this is accurate only to within the gateway''s introspection cache TTL, not per-request.';
