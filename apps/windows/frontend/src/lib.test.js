// Unit tests for the pure frontend helpers. Run with: npm test
// (node --test, zero extra dependencies — no DOM required).
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { escapeHtml, formatBytes, validateHop, validateTransport } from './lib.js'

test('escapeHtml neutralizes markup', () => {
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;')
  assert.equal(escapeHtml('a & "b"'), 'a &amp; &quot;b&quot;')
  assert.equal(escapeHtml(null), '')
  assert.equal(escapeHtml(undefined), '')
  assert.equal(escapeHtml(42), '42')
})

test('formatBytes scales units', () => {
  assert.equal(formatBytes(0), '0 B')
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(2048), '2.0 KB')
  assert.equal(formatBytes(5 * 1024 * 1024), '5.00 MB')
  assert.equal(formatBytes(3 * 1024 ** 3), '3.00 GB')
  assert.equal(formatBytes('not-a-number'), '0 B')
})

test('validateTransport accepts known underlays and normalizes case', () => {
  for (const t of ['udp', 'tcp', 'websocket', 'wss']) {
    assert.deepEqual(validateTransport(t), { ok: true, transport: t })
  }
  assert.deepEqual(validateTransport('  TCP '), { ok: true, transport: 'tcp' })
  assert.deepEqual(validateTransport(''), { ok: true, transport: 'udp' })
})

test('validateTransport rejects unknown underlays', () => {
  const r = validateTransport('quic')
  assert.equal(r.ok, false)
  assert.match(r.error, /udp\/tcp\/websocket\/wss/)
})

test('validateHop normalizes spread and bounds count', () => {
  assert.deepEqual(validateHop('3', '0'), { ok: true, hopCount: 3, hopSpread: 2048 })
  assert.deepEqual(validateHop('1', ''), { ok: true, hopCount: 1, hopSpread: 0 })
  assert.deepEqual(validateHop('16', '4096'), { ok: true, hopCount: 16, hopSpread: 4096 })
})

test('validateHop rejects out-of-range counts', () => {
  for (const bad of ['0', '17', '-1', 'abc']) {
    const r = validateHop(bad, '100')
    assert.equal(r.ok, false, `hopCount ${bad} should be rejected`)
    assert.match(r.error, /1-16/)
  }
})
