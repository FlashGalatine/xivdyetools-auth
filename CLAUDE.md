# xivdyetools-auth

Shared authentication utilities for the xivdyetools ecosystem.

## Overview

This package consolidates duplicated authentication patterns across the ecosystem:
- JWT verification using HMAC-SHA256 (HS256)
- HMAC signing utilities for bot request authentication
- Timing-safe comparison to prevent timing attacks
- Discord Ed25519 signature verification wrapper

## Architecture

### JWT Verification
- Uses Web Crypto API (no external JWT libraries)
- Algorithm validation prevents confusion attacks (only accepts HS256)
- Verifies expiration by default, with option for signature-only verification

### HMAC Signing
- HMAC-SHA256 via `crypto.subtle`
- Bot signature format: `${timestamp}:${userDiscordId}:${userName}`
- Timestamp validation with configurable max age and clock skew tolerance

### Timing-Safe Comparison
- Uses `crypto.subtle.timingSafeEqual()` when available (Cloudflare Workers)
- XOR-based fallback for other environments
- Pads shorter array to prevent length-based timing leaks

### Discord Verification
- Wraps `discord-interactions` library's `verifyKey()`
- Body size validation (100KB default limit)
- Content-Length header check before reading body

## Dependencies

- `@xivdyetools/crypto` - Base64URL encoding/decoding
- `discord-interactions` - Ed25519 signature verification

## Module Exports

- `@xivdyetools/auth` - Main exports (all utilities)
- `@xivdyetools/auth/jwt` - JWT-specific exports
- `@xivdyetools/auth/hmac` - HMAC-specific exports
- `@xivdyetools/auth/timing` - Timing-safe comparison
- `@xivdyetools/auth/discord` - Discord verification

## Commands

```bash
npm run build       # Build TypeScript
npm run type-check  # Type check without emitting
npm test            # Run tests
npm run test:coverage  # Run tests with coverage
```

## Security Notes

- JWT creation intentionally NOT included (stays in oauth service)
- Algorithm validation is critical for HS256 - never skip
- Timing-safe comparison must be used for signature verification
- Fail-open behavior on errors trades security for availability
