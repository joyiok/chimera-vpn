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

// STATUS_TEXT renders the badge copy for each normalized state.
export const STATUS_TEXT = {
  disconnected: '未连接',
  connecting: '连接中',
  connected: '已连接',
  error: '错误',
}

// normalizeStatus maps any backend status string onto the four UI states.
// Unknown payloads (e.g. "error: detail") must surface as an error state,
// never as a green "connected" badge.
export function normalizeStatus(status) {
  const s = String(status ?? '').trim()
  if (['disconnected', 'connecting', 'connected'].includes(s)) return s
  return 'error'
}

// statusLabel returns the human-readable badge copy for a normalized
// state.
export function statusLabel(normalized) {
  return STATUS_TEXT[normalized] ?? normalized
}

// connectLabelFor picks the connect-button caption for a normalized
// state.
export function connectLabelFor(normalized) {
  if (normalized === 'connected') return '断开'
  if (normalized === 'connecting') return '连接中…'
  if (normalized === 'error') return '重试'
  return '连接'
}

// looksLikeApp detects the Wails-bound backend across binding layouts
// (window.go.main.ChimeraApp vs .App vs chimera namespace).
export function looksLikeApp(obj) {
  return !!obj && typeof obj.Start === 'function' && typeof obj.Status === 'function'
}
