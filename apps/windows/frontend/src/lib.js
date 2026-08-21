// Pure helpers shared by main.js and the node:test suite (lib.test.js).
// No DOM access here: everything must run under plain Node.

// escapeHtml renders untrusted strings safe for innerHTML interpolation.
export function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// formatBytes renders a traffic counter for the status bar.
export function formatBytes(n) {
  const v = Number(n) || 0
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  if (v < 1024 * 1024 * 1024) return `${(v / 1024 / 1024).toFixed(2)} MB`
  return `${(v / 1024 / 1024 / 1024).toFixed(2)} GB`
}

// validateTransport normalizes the transport input. Returns
// { ok, transport } or { ok: false, error }.
export function validateTransport(raw) {
  const t = String(raw || '').trim().toLowerCase() || 'udp'
  if (!['udp', 'tcp', 'websocket', 'wss'].includes(t)) {
    return { ok: false, error: '传输只能是 udp/tcp/websocket/wss。' }
  }
  return { ok: true, transport: t }
}

// validateHop normalizes port-hopping options from the form.
// Returns { ok, hopCount, hopSpread } or { ok: false, error }.
export function validateHop(hopCountRaw, hopSpreadRaw) {
  const hopCount = Number.parseInt(hopCountRaw ?? '1', 10)
  const spreadRaw = Number.parseInt(hopSpreadRaw || '0', 10)
  if (!Number.isInteger(hopCount) || hopCount < 1 || hopCount > 16) {
    return { ok: false, error: '端口跳跃数必须在 1-16 之间。' }
  }
  const hopSpread = hopCount > 1 && spreadRaw <= 0 ? 2048 : spreadRaw
  return { ok: true, hopCount, hopSpread }
}
