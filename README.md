# JWT Pentest Helper

A web tool for **authorized** JWT testing: decoding, editing the payload/header, and generating test tokens for common vulnerability classes.

## Covered Attack Types

- Unverified Signature
- Flawed Signature Verification (`alg=none`)
- Algorithm Confusion (`RS↔HS`)
- Weak Signing Key
- `jwk` Header Injection
- `jku` Header Injection
- `kid` Header Path Traversal

## Installation and Launch

### Option 1: Locally without a container

Open `index.html` in a modern browser.

### Option 2: Docker Compose

```bash
docker compose up --build
```

After startup, open: `http://localhost`

## Basic Usage Scenario

1. Paste the original JWT.
2. Click **Decode token**.
3. Edit the payload/header if needed.
4. Select the required attack preset.
5. Fill in the attack-specific input field if required by the selected preset.
6. Click **Generate** and use the generated token in your test.

## Screenshots

<img width="750" height="744" alt="image" src="https://github.com/user-attachments/assets/a44461e8-fa88-4bd9-bb67-bd5432df9a3f" />
<img width="747" height="787" alt="image" src="https://github.com/user-attachments/assets/ef687747-cd09-4bc2-8d48-babb5d3042b8" />

## Disclaimer

Use this tool only on systems for which you have explicit permission to perform testing.
