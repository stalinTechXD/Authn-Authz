# JWT Authentication & Authorization

This project demonstrates **stateless authentication** with JSON Web Tokens (JWT)
and **authorization** using roles and policies in ASP.NET Core.

## What is a JWT?

A JWT is a signed string made of three Base64Url-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

| Part | Contains | Example |
|------|----------|---------|
| Header | Signing algorithm & type | `{ "alg": "HS256", "typ": "JWT" }` |
| Payload | Claims about the user | `{ "sub": "admin", "role": "Admin", "department": "IT", "exp": 1699999999 }` |
| Signature | `HMACSHA256(header + "." + payload, secretKey)` | integrity check |

The **signature** guarantees the token was not tampered with. If any character in
the header or payload changes, the recomputed signature no longer matches and the
token is rejected.

## The flow

1. **Login** — `POST /auth/login` with username/password. The server validates the
   credentials and issues a signed JWT (`AuthController.GenerateJwtToken`).
2. **Store** — the client keeps the token (memory, secure storage, etc.).
3. **Call** — every request sends `Authorization: Bearer <token>`.
4. **Validate** — the `AddJwtBearer` middleware in `Program.cs` re-computes the
   signature with the shared secret (`Jwt:Key`) and checks issuer, audience, and
   expiry. On success it builds `User` (a `ClaimsPrincipal`).
5. **Authorize** — attributes like `[Authorize(Roles = "Admin")]` or
   `[Authorize(Policy = "HrDepartment")]` decide what the user may access.

## Why is JWT stateless?

**Stateless means the server stores nothing about the session between requests.**

- Traditional session cookies store session data server-side; the cookie is just an
  ID that must be looked up on every request (**stateful**).
- A JWT carries all needed data **inside the token**, protected by the signature.
  The server only **verifies the signature** — no database or memory lookup.

### Benefits
- **Scalable** — any server instance sharing the secret key can validate the token,
  so load balancing needs no shared session store.
- **Fast** — validation is a cryptographic check, not a DB round-trip.
- **Decoupled** — the issuer and the consumer can be different services.

### Trade-off
- Tokens **cannot be easily revoked** before they expire, because nothing is stored
  server-side. Mitigate with short lifetimes (`Jwt:ExpiryMinutes`), refresh tokens,
  or a revocation deny-list.

## Try it

Use `Authn&Authz.http`:

1. `POST /auth/login` (e.g. `admin` / `admin123`) → copy the `token`.
2. `GET /secure/profile` with `Authorization: Bearer <token>`.
3. `GET /auth/decode` with the same header to inspect the header/payload and see
   that no session lookup happens.

## Demo users

| Username | Password | Role  | Department |
|----------|----------|-------|------------|
| admin    | admin123 | Admin | IT         |
| hruser   | hr123    | User  | HR         |
| john     | john123  | User  | Sales      |

> Educational only: passwords are plain text and the signing key is in
> `appsettings.json`. In production, hash passwords (ASP.NET Core Identity) and keep
> secrets in a secure store (user-secrets, Azure Key Vault).
