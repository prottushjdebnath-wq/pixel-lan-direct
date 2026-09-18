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

  await t.test('Canonicalizes command parameters deterministically with sorted keys and length prefixing', () => {
    const emptyParams = cryptoClient.canonicalizeParameters({});
    assert.strictEqual(emptyParams, '');

    const params = { y: 200, x: 100 };
    const canon = cryptoClient.canonicalizeParameters(params);
    assert.strictEqual(canon, '1:x=3:100,1:y=3:200');

    const textParams = { text: 'Hello & World' };
    const canonText = cryptoClient.canonicalizeParameters(textParams);
    assert.strictEqual(canonText, '4:text=13:Hello & World');
  });

  await t.test('Builds exact canonical command payload with length-prefixed fields', () => {
    const canonical = cryptoClient.buildCanonicalCommandPayload({
      protocolContext: PROTOCOL_CONTEXT,
      commandId: 'cmd-test-1',
      sessionId: 'session-123',
      epoch: 1,
      seqNum: 1,
      timestamp: 1726000000000,
      action: 'TAP',
      parameters: { x: 100, y: 200 },
      controllerId: 'ctl-unit-test',
      controllerPubkey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'
    });

    const expected = '20:PIXEL_SECURE_AUTH_V1|10:cmd-test-1|11:session-123|1:1|1:1|13:1726000000000|3:TAP|19:1:x=3:100,1:y=3:200|13:ctl-unit-test|39:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...';
    assert.strictEqual(canonical, expected);
  });

  await t.test('Signs management command and verifies signature with WebCrypto ECDSA P-256 public key', async () => {
    const cmd = {
      type: 'COMMAND',
      command_id: 'cmd-exec-1',
      session_id: 'session-uuid-999',
      epoch: 42,
      seq_num: 1,
      timestamp: 1726000000000,
      action: 'TAP',
      parameters: { x: 100, y: 200 }
    };

    const signature = await cryptoClient.signCommand(cmd);
    assert.ok(typeof signature === 'string');
    assert.ok(signature.length > 20);

    const canonical = cryptoClient.buildCanonicalCommandPayload({
      protocolContext: PROTOCOL_CONTEXT,
      commandId: cmd.command_id,
      sessionId: cmd.session_id,
      epoch: cmd.epoch,
      seqNum: cmd.seq_num,
      timestamp: cmd.timestamp,
      action: cmd.action,
      parameters: cmd.parameters,
      controllerId: cryptoClient.controllerId,
      controllerPubkey: cryptoClient.publicKeyDerB64
    });

    const sigBytes = Buffer.from(signature, 'base64');
    const isValid = await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      cryptoClient.keyPair.publicKey,
      sigBytes,
      new TextEncoder().encode(canonical)
    );
    assert.strictEqual(isValid, true);

    // Tampering action invalidates signature
    const tamperedCanonical = canonical.replace('3:TAP', '8:NAV_BACK');
    const isTamperedValid = await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      cryptoClient.keyPair.publicKey,
      sigBytes,
      new TextEncoder().encode(tamperedCanonical)
    );
    assert.strictEqual(isTamperedValid, false);
  });
});
