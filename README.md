# JWT Pentest Helper

A lightweight single-page web tool to assist **authorized** JWT security testing.

## Features

- Single page UI (`index.html`) with:
  - Source JWT input + decoding (header/payload).
  - Payload editor for crafted variants.
  - Attack presets mapped to these labs:
    - JWT authentication bypass via unverified signature.
    - JWT authentication bypass via flawed signature verification.
    - JWT authentication bypass via weak signing key.
    - JWT authentication bypass via jwk header injection.
    - JWT authentication bypass via jku header injection.
    - JWT authentication bypass via kid header path traversal.

- Dynamic attack-specific input:
  - Input field appears only for attacks that require user data.
  - Example: Weak Signing Key requires an explicit user-provided secret.

- HS256 signing helper implemented in browser via Web Crypto API.

## Run

### Option 1: Open directly

Open `index.html` directly in a modern browser.

### Option 2: Docker Compose

```bash
docker compose up --build
```

Then open: `http://localhost:8080`

## Disclaimer

Use this tool only on systems you own or have explicit written permission to test.
