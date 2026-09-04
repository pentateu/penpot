# Penpot ISWE fork — JWT + OIDC (iswe/main)

Base: upstream `penpot/penpot` tag `2.17.2` (`1d2c37e52c`).
Branch: `iswe/main` (this branch). Live image: `ghcr.io/pentateu/penpot-backend:2.17-iswe`.

## What -iswe adds over stock (layer-diff)

Stock `penpotapp/backend:2.17`:
- Id `sha256:770b55f6e51bfcee49152b30858ca6a47143256de8d43953a50b952b5c60bb55`
- Digest `penpotapp/backend@sha256:770b55f6e51bfcee49152b30858ca6a47143256de8d43953a50b952b5c60bb55`

-iswe `penpotapp/backend:2.17-iswe` (pre-ghcr, aorus-local):
- Id `sha256:e389b9712b49c9d6a3258ebb819cf8aca8cee85fec030cbe231b11afe7ba61f6`
- One top layer: `COPY penpot.jar.patched.final /opt/penpot/backend/penpot.jar` (109MB).
- All lower layers identical to stock (see `docker history`).

Patched files in jar (decompiled 2026-09-04, `~/penpot-backups/jar-src`):
- `backend/src/app/auth.clj` (+JWT verify-jwt, RS256-only — this branch fixes HS fallback)
- `backend/src/app/http/session.clj` (+Bearer JWT branch, email->profile, legacy fallback 2w)
- `backend/src/app/config.clj` (+`:jwt-verify-url :jwt-issuer :jwt-audience :oidc-jwks`)

Upstream archaeology vs tag `2.17.2`:
- `auth.clj` upstream 27 lines → this branch ~210 lines (JWT only, no other changes).
- `session.clj` upstream 362 → 396 (+34 Bearer branch).
- `config.clj` upstream 379 → 383 (+4 JWT keys, nrepl kept).
- `middleware.clj`, `rpc/commands/auth.clj`, `auth/oidc.clj`, `auth/ldap.clj` identical.

## Verifier contract (locked)

- RS256-only. Reject none, HS256/384/512, RS384/512, ES*, PS*, EdDSA. No secret fallback.
- Exact `iss` `https://auth.iswe.co.nz/application/o/penpot/` (trailing slash).
- Exact `aud` `penpot` as string. Arrays reject.
- `exp` required, enforced with 60s leeway. Missing `exp` rejects.
- `nbf` enforced with 60s leeway when present.
- `jwks_uri` from `PENPOT_JWT_VERIFY_URL` → `PENPOT_OIDC_JWKS` → `PENPOT_OIDC_JWKS_URI`,
  else `.well-known` discovery, else `issuer + /jwks/`. Never hardcode.
- `kid` rotation: 10m cache TTL, single refetch on kid miss.
- `sub` authority: Authentik `sub_mode user_email`, `issuer_mode per_provider`.
  Email source `email` → `preferred_username` → `upn` → `sub` (if email-shaped),
  lowercased, `lower(email)` profile match. Unknown email logs `no-profile`, yields nil.
- Errors mapped: return nil, log hint (`jwt: verified` / `jwt: invalid ...`), no stack.

## Build

Context dir: repo root. Dockerfile: `iswe/Dockerfile.backend`.
Base: `penpotapp/backend:2.17@sha256:770b55f6e51bfcee49152b30858ca6a47143256de8d43953a50b952b5c60bb55` (pinned, amd64).

```sh
# ghcr login (token in env, never in diff)
echo "$GHCR_TOKEN" | docker login ghcr.io -u pentateu --password-stdin
docker build -t ghcr.io/pentateu/penpot-backend:2.17-iswe -f iswe/Dockerfile.backend .
docker push ghcr.io/pentateu/penpot-backend:2.17-iswe
docker inspect ghcr.io/pentateu/penpot-backend:2.17-iswe --format '{{index .RepoDigests 0}}'
```

Local JWT smoke (after build, before push):
```sh
python3 iswe/test_jwt_verify.py
# plus live Bearer probe (needs PLATFORM_TOKEN via 600 file, never argv):
# curl -H "Authorization: Bearer $SEAT_JWT" -H "Content-Type: application/json" \
#   -d '{}' https://penpot-alpha.iswe.co.nz/api/rpc/command/get-profile
```

## Tests

`iswe/test_jwt_verify.py` (stdlib + cryptography only):
- valid verifies, wrong aud rejects, unknown email no-profile,
  expired rejects, none/HS256 rejects, wrong iss rejects.
Run: `python3 iswe/test_jwt_verify.py` (expect 6 ok).

## Pins (rollback)

- Backend stock: `sha256:770b55f6e51bfcee49152b30858ca6a47143256de8d43953a50b952b5c60bb55`
- Backend iswe (aorus-local): `sha256:e389b9712b49c9d6a3258ebb819cf8aca8cee85fec030cbe231b11afe7ba61f6`
- Frontend `penpotapp/frontend:2.17` `sha256:94fa2864d8fc0cd62245af95c03cca89306a7fd23c206a98a3e9dc9a376ea27e`
- Exporter `penpotapp/exporter:2.17` `sha256:72a8061e88069b9baf0767bc11fbf3310d2527bb5964ca084cf8c844d84306c8`
- MCP `penpotapp/mcp:2.17` `sha256:84f3f07ead11745ad95c2c1db90d33d00c550cff76844791ca4389d307f1be37`
- Postgres `postgres:15` `sha256:9b1d34adbce1dd07ee6e94b4a2cf698884b89bd44a6c9c12f5da8f3acbfe4957`
- Valkey `valkey/valkey:8.1` `sha256:86273fe4ddc2355a654511adba89344ae1d229fd7b0c58a766a29c89c206e1ce`
- Mailcatcher `sj26/mailcatcher:latest` `sha256:5d153a4daadf0c266f29c3856085741f06ca1e3768671f4267622d3e3ffe5564`
- Never short IDs, never floating tags. Never `docker system prune` on aorus until push.
