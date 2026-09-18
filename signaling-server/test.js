const { test } = require('node:test');
const assert = require('node:assert');
const { WebSocket } = require('ws');
const { createSignalingServer } = require('./server.js');

test('Signaling Server - Ephemeral WebRTC exchange and strict security filters', async (t) => {
  const { server, wss } = createSignalingServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const wsUrl = `ws://127.0.0.1:${port}/signaling`;

  t.after(() => {
    wss.close();
    server.close();
  });

  await t.test('Registers device and controller, and relays SDP offer/answer', async () => {
    const deviceWs = new WebSocket(wsUrl);
    const controllerWs = new WebSocket(wsUrl);

    await Promise.all([
      new Promise((res) => deviceWs.on('open', res)),
      new Promise((res) => controllerWs.on('open', res))
    ]);

    // Device registers
    deviceWs.send(JSON.stringify({
      type: 'REGISTER',
      role: 'device',
      device_id: 'pixel-test-device'
    }));

    const devRegMsg = await new Promise((res) => deviceWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(devRegMsg.type, 'REGISTERED');
    assert.strictEqual(devRegMsg.id, 'pixel-test-device');

    // Controller registers
    controllerWs.send(JSON.stringify({
      type: 'REGISTER',
      role: 'controller',
      controller_id: 'ctl-test-1',
      target_device_id: 'pixel-test-device'
    }));

    const ctlRegMsg = await new Promise((res) => controllerWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(ctlRegMsg.type, 'REGISTERED');
    assert.strictEqual(ctlRegMsg.target_status, 'online');

    // Controller sends SDP OFFER
    controllerWs.send(JSON.stringify({
      type: 'OFFER',
      sdp: 'v=0\r\no=- 12345 2 IN IP4 127.0.0.1...'
    }));

    const receivedOffer = await new Promise((res) => deviceWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(receivedOffer.type, 'OFFER');
    assert.ok(receivedOffer.sdp.includes('v=0'));

    // Device responds with SDP ANSWER
    deviceWs.send(JSON.stringify({
      type: 'ANSWER',
      sdp: 'v=0\r\no=- 67890 2 IN IP4 127.0.0.1...'
    }));

    const receivedAnswer = await new Promise((res) => controllerWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(receivedAnswer.type, 'ANSWER');

    // ICE restart signal
    controllerWs.send(JSON.stringify({
      type: 'ICE_RESTART',
      reason: 'NETWORK_CHANGE_WIFI_TO_CELLULAR'
    }));

    const receivedRestart = await new Promise((res) => deviceWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(receivedRestart.type, 'ICE_RESTART');
    assert.strictEqual(receivedRestart.reason, 'NETWORK_CHANGE_WIFI_TO_CELLULAR');

    deviceWs.close();
    controllerWs.close();
  });

  await t.test('Strictly drops management command and terminates connection', async () => {
    const maliciousWs = new WebSocket(wsUrl);
    await new Promise((res) => maliciousWs.on('open', res));

    maliciousWs.send(JSON.stringify({
      type: 'COMMAND',
      action: 'TAP',
      parameters: { x: 100, y: 200 }
    }));

    const err = await new Promise((res) => maliciousWs.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(err.type, 'ERROR');
    assert.strictEqual(err.code, 'FORBIDDEN_MESSAGE_TYPE');

    // Connection must be closed with 1008 policy violation
    const closeCode = await new Promise((res) => maliciousWs.once('close', (code) => res(code)));
    assert.strictEqual(closeCode, 1008);
  });

  await t.test('Strictly drops forbidden screenshot/telemetry payloads in signaling', async () => {
    const ws = new WebSocket(wsUrl);
    await new Promise((res) => ws.on('open', res));

    ws.send(JSON.stringify({
      type: 'OFFER',
      image_base64: 'fake-screenshot-data'
    }));

    const err = await new Promise((res) => ws.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(err.type, 'ERROR');
    assert.strictEqual(err.code, 'FORBIDDEN_PAYLOAD_CONTENT');

    const closeCode = await new Promise((res) => ws.once('close', (code) => res(code)));
    assert.strictEqual(closeCode, 1008);
  });

  await t.test('Strictly drops deeply nested forbidden parameters and terminates connection', async () => {
    const ws = new WebSocket(wsUrl);
    await new Promise((res) => ws.on('open', res));

    ws.send(JSON.stringify({
      type: 'ICE_CANDIDATE',
      sdpMid: '0',
      sdpMLineIndex: 0,
      nested_data: [
        { harmless: 'value' },
        { sub_nested: { command_id: 'leaked-command-id' } }
      ]
    }));

    const err = await new Promise((res) => ws.once('message', (d) => res(JSON.parse(d))));
    assert.strictEqual(err.type, 'ERROR');
    assert.strictEqual(err.code, 'FORBIDDEN_PAYLOAD_CONTENT');
    assert.ok(err.message.includes('command_id'));

    const closeCode = await new Promise((res) => ws.once('close', (code) => res(code)));
    assert.strictEqual(closeCode, 1008);
  });
});
