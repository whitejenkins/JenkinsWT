# JWT Pentest Helper

A lightweight single-page web tool to assist **authorized** JWT security testing.

## Features

- Single page UI (`index.html`) with source JWT decode, payload editing, attack presets, and generated token output.
- Attack presets mapped to labs:
  - JWT authentication bypass via unverified signature.
  - JWT authentication bypass via flawed signature verification.
  - JWT authentication bypass via weak signing key.
  - JWT authentication bypass via jwk header injection.
  - JWT authentication bypass via jku header injection.
  - JWT authentication bypass via kid header path traversal.
- Dynamic attack-specific inputs shown only when needed.

## JWK header injection: algorithm generation options

Inside **jwk Header Injection** you can choose key generation/signing algorithm:
- `HS256`, `HS384`, `HS512`
- `RS256`, `RS384`, `RS512`
- `PS256`, `PS384`, `PS512`
- `ES256`, `ES384`, `ES512`
- `EdDSA` (Ed25519)

The app now follows a simple flow: paste JWT -> choose algorithm -> click generate (or Embed JWK & Sign). It auto-generates key material, embeds a minimal public JWK, removes conflicting header params (`kid`, `jku`), and signs automatically.
For `jku Header Injection`, the Attack-specific input now also contains step-by-step guidance, JWKS generation output, and action buttons to generate key/copy JWKS/sign token.
Weak Signing Key step guide now includes Hashcat command:
`hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`

Kid Path Traversal flow is now fully automated: tool sets traversal `kid` and signs with a null-byte key automatically (no manual key/header edits).



## Run

### Option 1: Open directly

Open `index.html` directly in a modern browser.

### Option 2: Docker Compose

```bash
docker compose up --build
```

Then open: `http://localhost`

## Disclaimer

Use this tool only on systems you own or have explicit written permission to test.
