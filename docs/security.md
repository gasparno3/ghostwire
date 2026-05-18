# GhostWire Security

## Overview

GhostWire uses multiple layers of cryptography to protect both authentication and tunnel traffic.

## Authentication

### Threat Model

A passive eavesdropper or TLS-terminating proxy (e.g. CloudFlare) sees WebSocket frame contents in plaintext. Without protection, a MITM who controls the RSA key exchange could substitute their own public key, intercept the auth token, and authenticate independently as a legitimate client.

### PBKDF2 Challenge-Response

GhostWire prevents token extraction through a challenge-response mechanism:

1. Server generates a random 32-byte `auth_salt` per connection
2. Server sends its RSA public key **with the salt appended**
3. Client computes `derived_key = PBKDF2-SHA256(token, auth_salt, iterations=100_000, dklen=32)`
4. Client RSA-encrypts `derived_key + role + child_id` with the server's public key and sends it
5. Server decrypts, runs the same PBKDF2 derivation on the expected token, and compares with `secrets.compare_digest`

**What this prevents:** Even if a MITM intercepts and decrypts the auth message (by substituting its RSA key), it only obtains `PBKDF2(token, salt)` — a one-way derived value that cannot be reversed to recover the raw token. The token has ~120 bits of entropy (nanoid, 20 chars × 64-symbol alphabet), making offline brute force completely infeasible regardless of salt knowledge.

**Replay protection:** Each connection uses a fresh random `auth_salt`, so a captured derived key is useless for subsequent connections.

## Session Encryption

After authentication:

1. Client sends its RSA-2048 public key
2. Server generates a random 256-bit session key
3. Server RSA-encrypts the session key with the client's public key and sends it
4. Client decrypts the session key
5. All tunnel traffic is encrypted with **AES-256-GCM** using this session key, with random 96-bit nonces per frame

The AES-256-GCM authenticated encryption provides both confidentiality and integrity — any tampering with tunnel frames is detected and the frame is rejected.

## Transport Layer

- **WebSocket (default):** Uses `wss://` (TLS) via nginx or directly; the TLS layer protects the key exchange from passive observers
- **gRPC / HTTP/2:** Same TLS requirement
- **HTTP per-request:** Uses HTTPS for all requests; the full RSA auth and session key exchange happen on the `open`/`auth`/`key` HTTP requests before any tunnel data flows, so no streaming connection is required for the security handshake; subsequent `upload` (POST) and `poll` (GET) requests carry AES-256-GCM encrypted GhostWire frames
- **CloudFlare:** TLS is terminated at CloudFlare's edge; the RSA key exchange and PBKDF2 auth ensure tokens remain secret even from CloudFlare; this applies to all four transports including HTTP per-request

## Token Security

- Tokens are generated with `nanoid(size=20)` using a 64-symbol alphabet (~120 bits of entropy)
- Tokens are stored only in the server's config file (`/etc/ghostwire/server.toml`) and the client's config file
- Tokens are never transmitted in plaintext — always PBKDF2-derived and RSA-encrypted
- Token comparison uses `secrets.compare_digest` to prevent timing attacks

## Server Key Pinning (MITM Protection)

By default, the server generates a fresh RSA-2048 keypair on each startup. While PBKDF2 prevents token recovery, a MITM who can intercept the key exchange at the protocol layer could still transparently proxy the connection without either side knowing.

Key pinning closes this gap:

**Server** — set `pinned_private_key` to a PEM private key file path:
```toml
pinned_private_key="/etc/ghostwire/server_private.pem"
```
The server loads and uses this fixed key every startup. Its public key is then stable and shareable with clients.

**Client** — set `pinned_server_public_key` to a PEM public key file path:
```toml
pinned_server_public_key="/etc/ghostwire/server_public.pem"
```
After receiving the server's public key during handshake, the client computes `SHA-256(DER(received_key))` and compares it against `SHA-256(DER(pinned_key))`. A mismatch aborts the connection with an error.

**Generating a persistent keypair:**
```bash
openssl genrsa -out server_private.pem 2048
openssl rsa -in server_private.pem -pubout -out server_public.pem
```
Copy `server_public.pem` to each client that should pin this server.

If neither option is set, behavior is unchanged from previous versions — the server generates ephemeral keys and the client skips fingerprint verification.

## Summary

| Layer | Mechanism |
|-------|-----------|
| Auth token protection | PBKDF2-SHA256 (100 000 iterations) + RSA-2048-OAEP |
| Session key exchange | RSA-2048-OAEP |
| Tunnel traffic | AES-256-GCM with per-frame random nonces |
| Transport (WebSocket) | TLS via `wss://` |
| Transport (HTTP/2 / gRPC) | TLS via `https://` |
| Transport (HTTP per-request) | TLS via `https://`; auth and key exchange on dedicated HTTP requests before data flows |
| Server identity | Optional RSA public key pinning via SHA-256 fingerprint comparison |
