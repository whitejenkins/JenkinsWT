# JWT Pentest Helper

A lightweight 2-page web tool to assist **authorized** JWT security testing.

## Features

1. **Input page** (`index.html`)
   - Paste a source JWT token.
   - Basic format validation.

2. **Attack lab page** (`attacks.html`)
   - Decodes JWT header and payload.
   - Lets you edit payload JSON.
   - Generates attack candidates mapped to these labs:
     - JWT authentication bypass via unverified signature.
     - JWT authentication bypass via flawed signature verification.
     - JWT authentication bypass via weak signing key.
     - JWT authentication bypass via jwk header injection.
     - JWT authentication bypass via jku header injection.
     - JWT authentication bypass via kid header path traversal.
   - Supports HS256 signing and optional RS256 signing when `privateJwk` is provided.

## Optional JSON input examples

- Weak key:
  - `{"secret":"secret1"}`
- JWK injection:
  - `{"publicJwk": { ... }, "privateJwk": { ... }}`
- JKU injection:
  - `{"jku":"https://attacker.example/jwks.json","kid":"attacker-key-1","privateJwk": { ... }}`

## Run

Open `index.html` directly in a modern browser.

## Disclaimer

Use this tool only on systems you own or have explicit written permission to test.
