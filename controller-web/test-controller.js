const { test } = require('node:test');
const assert = require('node:assert');
const { webcrypto } = require('node:crypto');
const { ControllerCrypto, PROTOCOL_CONTEXT } = require('./crypto.js');

test('Controller WebCrypto & Context-Bound Authentication', async (t) => {
  const cryptoClient = new ControllerCrypto();

  await t.test('Generates persistent ECDSA P-256 identity with non-extractable semantics', async () => {
    // Inject node:crypto's subtle crypto
    const id = await cryptoClient.init(webcrypto.subtle);
    assert.ok(id.controllerId.startsWith('ctl-'));
    assert.ok(id.publicKeyDerB64.length > 50);
    assert.ok(id.fingerprint.includes(':'));
  });

  await t.test('Computes exact canonical pairing transcript hash', async () => {
    const pixelId = 'pixel-managed-device';
    const pixelPubkey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...fakePubkey';
    const pin = '123456';
    const nonce = '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';

    const hash = await cryptoClient.computePairingTranscriptHash(pixelId, pixelPubkey, pin, nonce);
    assert.strictEqual(typeof hash, 'string');
    assert.strictEqual(hash.length, 64); // SHA-256 hex string

    // Canonical verification: manual calculation must match
    const canonical = `${pixelId}:${pixelPubkey}:${cryptoClient.publicKeyDerB64}:${pin}:${nonce}`;
    const expectedBuf = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    const expectedHex = Array.from(new Uint8Array(expectedBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    assert.strictEqual(hash, expectedHex);
  });

  await t.test('Context-bound challenge response signs bound parameters', async () => {
    const challenge = {
      type: 'CHALLENGE',
      protocol_context: PROTOCOL_CONTEXT,
      session_id: 'session-uuid-999',
      epoch: 42,
      nonce: 'ephemeral-nonce-abc',
      timestamp: 1726000000000,
      pixel_id: 'pixel-managed-device',
      pixel_pubkey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...pixelPub'
    };

    const authResp = await cryptoClient.signChallenge(challenge);
    assert.strictEqual(authResp.type, 'AUTH_RESPONSE');
    assert.strictEqual(authResp.protocol_context, PROTOCOL_CONTEXT);
    assert.strictEqual(authResp.session_id, 'session-uuid-999');
    assert.strictEqual(authResp.controller_id, cryptoClient.controllerId);
    assert.strictEqual(authResp.controller_pubkey, cryptoClient.publicKeyDerB64);
    assert.ok(authResp.signature.length > 20);

    // Verify signature using the public key
    const canonicalPayload = `${PROTOCOL_CONTEXT}:${challenge.session_id}:${challenge.nonce}:${challenge.timestamp}:${challenge.pixel_id}:${challenge.pixel_pubkey}:${cryptoClient.controllerId}:${cryptoClient.publicKeyDerB64}`;
    const sigBytes = Buffer.from(authResp.signature, 'base64');

    const isValid = await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      cryptoClient.keyPair.publicKey,
      sigBytes,
      new TextEncoder().encode(canonicalPayload)
    );

    assert.strictEqual(isValid, true);
  });
});
