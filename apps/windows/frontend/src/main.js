import './style.css'
import { escapeHtml, formatBytes, validateHop, validateTransport, normalizeStatus, statusLabel, connectLabelFor, looksLikeApp } from './lib.js'

const SPARK_ACCENT = '#DC7A44'
const SPARK_OK = '#7FC581'
const SPARK_GRID = 'rgba(183, 168, 155, 0.16)'

// Wails v2 binds `type ChimeraApp struct` in package main as
// window.go.main.ChimeraApp, not window.go.main.App. v0.1.0 only
// looked for .App, so a real exe still logged "Wails 绑定不可用".
function getAPI() {
  const go = window.go
  if (!go) return null
  const named = [
    go.main?.ChimeraApp,
    go.main?.App,
    go.chimera?.ChimeraApp,
    go.chimera?.App,
  ]
  for (const candidate of named) {
    if (looksLikeApp(candidate)) return candidate
  }
  for (const ns of Object.values(go)) {
    if (!ns || typeof ns !== 'object') continue
    for (const candidate of Object.values(ns)) {
      if (looksLikeApp(candidate)) return candidate
    }
  }
  return null
}

function describeGoBindings() {
  if (!window.go) return 'window.go 未注入（不要用浏览器打开 HTML）'
  const parts = []
  for (const [ns, val] of Object.entries(window.go)) {
    const keys = val && typeof val === 'object' ? Object.keys(val).join(',') : typeof val
    parts.push(`${ns}:{${keys}}`)
  }
  return parts.length ? `window.go ${parts.join(' ')}` : 'window.go 为空'
}

async function waitForAPI(timeoutMs = 5000) {
  const start = Date.now()
  while (!getAPI()) {
    if (Date.now() - start > timeoutMs) return null
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return getAPI()
}

const $ = (id) => document.getElementById(id)
const els = {
  statusBadge: $('statusBadge'),
  statusText: $('statusText'),
  serverAddr: $('serverAddr'),
  serverName: $('serverName'),
  seedHex: $('seedHex'),
  generation: $('generation'),
  pskHex: $('pskHex'),
  transportInput: $('transportInput'),
  splitTunnel: $('splitTunnel'),
  portHopCount: $('portHopCount'),
  portHopSpread: $('portHopSpread'),
  connectBtn: $('connectBtn'),
  connectLabel: $('connectLabel'),
  saveServerBtn: $('saveServerBtn'),
  trayBtn: $('trayBtn'),
  inviteInput: $('inviteInput'),
  importBtn: $('importBtn'),
  copyInviteBtn: $('copyInviteBtn'),
  logs: $('logs'),
  clearLogsBtn: $('clearLogsBtn'),
  serverList: $('serverList'),
  txTotal: $('txTotal'),
  rxTotal: $('rxTotal'),
  txRate: $('txRate'),
  rxRate: $('rxRate'),
  spark: $('spark'),
}

const samples = []
let lastSent = 0
let lastRecv = 0
let lastTs = 0
let busy = false
let currentStatus = 'disconnected'

function svgIcon(name) {
  return `<svg class="ico" aria-hidden="true"><use href="#i-${name}"></use></svg>`
}

function log(message, level = 'info') {
  const line = document.createElement('div')
  line.className = `log ${level}`
  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  line.textContent = `[${time}] ${message}`
  const nearBottom = els.logs.scrollHeight - els.logs.scrollTop - els.logs.clientHeight < 36
  els.logs.appendChild(line)
  while (els.logs.children.length > 200) els.logs.firstChild.remove()
  if (nearBottom) els.logs.scrollTop = els.logs.scrollHeight
}

function clearLogs() {
  els.logs.innerHTML = ''
  log('日志已清空。', 'muted')
}

function renderStatus(status, detail = '') {
  const normalized = normalizeStatus(status)
  currentStatus = String(status ?? '').trim() || 'disconnected'

  els.statusBadge.className = `badge ${normalized}`
  const detailText = detail ? `：${detail}` : ''
  els.statusBadge.title = `${statusLabel(normalized)}${detailText}`
  els.statusText.textContent = statusLabel(normalized) + detailText

  els.connectBtn.dataset.state = normalized
  els.connectLabel.textContent = connectLabelFor(normalized)
  els.connectBtn.disabled = busy || normalized === 'connecting'
}

function setBusy(value) {
  busy = value
  els.connectBtn.classList.toggle('is-busy', value)
  els.connectBtn.disabled = value || currentStatus === 'connecting'
}

async function refreshStatus() {
  const api = getAPI()
  if (!api) return 'disconnected'
  try {
    const raw = await api.Status()
    const text = String(raw ?? '')
    const idx = text.indexOf(':')
    const status = (idx >= 0 ? text.slice(0, idx) : text).trim()
    const detail = (idx >= 0 ? text.slice(idx + 1) : '').trim()
    renderStatus(status, detail)
    return status || 'disconnected'
  } catch (e) {
    renderStatus('error', String(e))
    return 'error'
  }
}

function drawSpark() {
  const canvas = els.spark
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  const dpr = window.devicePixelRatio || 1
  const w = Math.max(1, canvas.clientWidth || canvas.parentElement.clientWidth)
  const h = Math.max(1, canvas.clientHeight || 58)
  canvas.width = Math.floor(w * dpr)
  canvas.height = Math.floor(h * dpr)
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)

  ctx.strokeStyle = SPARK_GRID
  ctx.lineWidth = 1
  ctx.beginPath()
  ctx.moveTo(0, h - 0.5)
  ctx.lineTo(w, h - 0.5)
  ctx.stroke()

  if (samples.length < 2) return

  const max = Math.max(1, ...samples)
  const points = samples.map((v, i) => ({
    x: (i / (samples.length - 1)) * w,
    y: h - (v / max) * (h - 8) - 4,
  }))
  const color = currentStatus === 'connected' ? SPARK_OK : SPARK_ACCENT

  const fill = ctx.createLinearGradient(0, 0, 0, h)
  fill.addColorStop(0, `${color}3D`)
  fill.addColorStop(1, `${color}00`)
  ctx.beginPath()
  ctx.moveTo(points[0].x, h)
  points.forEach((p) => ctx.lineTo(p.x, p.y))
  ctx.lineTo(points[points.length - 1].x, h)
  ctx.closePath()
  ctx.fillStyle = fill
  ctx.fill()

  ctx.strokeStyle = color
  ctx.lineWidth = 1.6
  ctx.lineJoin = 'round'
  ctx.lineCap = 'round'
  ctx.beginPath()
  points.forEach((p, i) => (i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y)))
  ctx.stroke()
}

async function refreshTraffic() {
  const api = getAPI()
  if (!api?.Traffic) return
  try {
    const t = await api.Traffic()
    const sent = Number(t.sent) || 0
    const recv = Number(t.recv) || 0
    const now = Date.now()
    let up = 0
    let down = 0
    if (lastTs) {
      const dt = Math.max(0.2, (now - lastTs) / 1000)
      up = Math.max(0, (sent - lastSent) / dt)
      down = Math.max(0, (recv - lastRecv) / dt)
    }
    lastSent = sent
    lastRecv = recv
    lastTs = now
    els.txTotal.textContent = formatBytes(sent)
    els.rxTotal.textContent = formatBytes(recv)
    els.txRate.textContent = `${formatBytes(up)}/s`
    els.rxRate.textContent = `${formatBytes(down)}/s`
    samples.push(up + down)
    if (samples.length > 60) samples.shift()
    drawSpark()
  } catch {
    // stub build has Traffic but zeros; network status keeps its own polling.
  }
}

function renderServers(list) {
  const items = Array.isArray(list) ? list : []
  if (!items.length) {
    els.serverList.innerHTML =
      '<div class="empty">还没有保存的入口。连上一次，或点「保存入口」。</div>'
    return
  }
  const current = els.serverAddr.value.trim().toLowerCase()
  els.serverList.innerHTML = ''
  for (const s of items) {
    const addr = String(s.addr || s.Addr || '').trim()
    const name = String(s.name || s.Name || '').trim() || addr
    if (!addr) continue

    const row = document.createElement('div')
    row.className = 'server-row'
    if (current && addr.toLowerCase() === current) row.classList.add('is-active')

    const pick = document.createElement('button')
    pick.type = 'button'
    pick.className = 'pick'
    pick.title = `使用入口 ${addr}`
    pick.innerHTML = `
      <span class="server-meta">
        ${svgIcon('server')}
        <span class="server-copy">
          <span class="name">${escapeHtml(name)}</span>
          <span class="addr">${escapeHtml(addr)}</span>
        </span>
      </span>`
    pick.addEventListener('click', () => {
      els.serverAddr.value = addr
      els.serverName.value = name
      renderServers(items)
      log(`已选用入口 ${addr}`)
    })

    const del = document.createElement('button')
    del.type = 'button'
    del.className = 'delete'
    del.title = `删除入口 ${addr}`
    del.setAttribute('aria-label', del.title)
    del.innerHTML = svgIcon('trash')
    del.addEventListener('click', async () => {
      const api = getAPI()
      if (!api) return
      try {
        await api.ForgetServer(addr)
        log(`已删除入口 ${addr}`)
      } catch (e) {
        log(`删除入口失败：${e}`, 'error')
      }
      await refreshServers()
    })

    row.append(pick, del)
    els.serverList.append(row)
  }
}

async function refreshServers() {
  const api = getAPI()
  if (!api?.Servers) return
  try {
    renderServers(await api.Servers())
  } catch (e) {
    log(`读取入口失败：${e}`, 'error')
  }
}

function validateForm() {
  const serverAddr = els.serverAddr.value.trim()
  const seedHex = els.seedHex.value.trim()
  const pskHex = els.pskHex.value.trim()
  const generation = Number.parseInt(els.generation.value || '0', 10)

  if (!serverAddr) return '请填写服务器地址。'
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) return 'Seed 必须是 64 位十六进制。'
  if (!Number.isInteger(generation) || generation < 0) return 'Generation 必须是非负整数。'
  if (!/^[0-9a-fA-F]{64}$/.test(pskHex)) return 'PSK 必须是 64 位十六进制。'
  return null
}

async function connect() {
  const api = getAPI()
  if (!api) {
    log(`Wails 绑定不可用，无法连接（${describeGoBindings()}）。`, 'warn')
    return
  }

  const invalid = validateForm()
  if (invalid) {
    log(invalid, 'warn')
    return
  }

  const serverAddr = els.serverAddr.value.trim()
  const seedHex = els.seedHex.value.trim()
  const pskHex = els.pskHex.value.trim()
  const generation = Number.parseInt(els.generation.value || '0', 10)
  const name = els.serverName.value.trim()
  const transport = els.transportInput.value.trim().toLowerCase() || 'udp'
  const splitTunnel = els.splitTunnel.checked
  const hop = validateHop(els.portHopCount.value, els.portHopSpread.value)
  if (!hop.ok) {
    log(hop.error, 'warn')
    return
  }
  const hopCount = hop.hopCount
  const hopSpreadFinal = hop.hopSpread

  const tr = validateTransport(transport)
  if (!tr.ok) {
    log(tr.error, 'warn')
    return
  }

  setBusy(true)
  renderStatus('connecting')
  log(`正在连接 server=${serverAddr} generation=${generation} transport=${tr.transport} split=${splitTunnel} hop=${hopCount}/${hopSpreadFinal}`)
  try {
    if (typeof api.StartWithOptions === 'function') {
      await api.StartWithOptions(seedHex, generation, pskHex, serverAddr, tr.transport, splitTunnel, hopCount, hopSpreadFinal)
    } else if (typeof api.StartAdvanced === 'function') {
      await api.StartAdvanced(seedHex, generation, pskHex, serverAddr, tr.transport, splitTunnel)
    } else if (typeof api.StartWithTransport === 'function') {
      await api.StartWithTransport(seedHex, generation, pskHex, serverAddr, tr.transport)
    } else {
      await api.Start(seedHex, generation, pskHex, serverAddr)
    }
    if (name) await api.RememberServer(name, serverAddr)
    log('连接成功。', 'ok')
    lastSent = 0
    lastRecv = 0
    lastTs = 0
    samples.length = 0
    await refreshServers()
  } catch (e) {
    log(`连接失败：${e}`, 'error')
  } finally {
    setBusy(false)
    await refreshStatus()
    await refreshTraffic()
  }
}

async function disconnect() {
  const api = getAPI()
  if (!api) return
  setBusy(true)
  log('正在断开连接…')
  try {
    await api.Stop()
    log('已断开。', 'ok')
  } catch (e) {
    log(`断开失败：${e}`, 'error')
  } finally {
    setBusy(false)
    await refreshStatus()
  }
}

function toggleSecret(btn) {
  const input = document.getElementById(btn.dataset.toggle)
  if (!input) return
  const show = input.type === 'password'
  input.type = show ? 'text' : 'password'
  btn.setAttribute('aria-pressed', String(show))
  btn.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye')
  btn.querySelector('span').textContent = show ? '隐藏' : '显示'
}

async function loadConfig(silent = false) {
  const api = getAPI()
  if (!api) return
  try {
    const cfg = await api.Config()
    els.serverAddr.value = cfg.serverAddr ?? ''
    els.seedHex.value = cfg.seedHex ?? ''
    els.generation.value = cfg.generation ?? 0
    els.pskHex.value = cfg.pskHex ?? ''
    els.transportInput.value = cfg.transport || 'udp'
    els.splitTunnel.checked = cfg.splitTunnel !== false
    els.portHopCount.value = cfg.portHopCount || 1
    els.portHopSpread.value = cfg.portHopSpread || 0
    if (Array.isArray(cfg.servers)) renderServers(cfg.servers)
    await refreshServers()
    if (!silent) log('配置已载入。')
  } catch (e) {
    log(`读取配置失败：${e}`, 'error')
  }
}

function applyProfile(p) {
  if (!p) return
  els.serverAddr.value = p.serverAddr || p.ServerAddr || ''
  els.seedHex.value = p.seedHex || p.SeedHex || ''
  els.pskHex.value = p.pskHex || p.PSKHex || p.pskhex || ''
  if (p.generation !== undefined && p.generation !== null) {
    els.generation.value = p.generation
  }
  if (p.name) els.serverName.value = p.name
}

async function importInvite(text) {
  const api = getAPI()
  if (!api) {
    log(`Wails 绑定不可用，无法导入（${describeGoBindings()}）。`, 'warn')
    return
  }
  const raw = (text ?? els.inviteInput.value).trim()
  if (!raw) {
    log('先粘贴邀请链接或 client.json。', 'warn')
    return
  }
  if (!api.ParseInvite) {
    log('当前 exe 太旧，请换 v0.1.2 及以后的 Windows 包。', 'error')
    return
  }
  try {
    const p = await api.ParseInvite(raw)
    applyProfile(p)
    els.inviteInput.value = raw
    log(`已导入 ${els.serverAddr.value}。密钥未写入日志。`, 'ok')
  } catch (e) {
    log(`导入失败：${e}`, 'error')
  }
}

async function copyInvite() {
  const api = getAPI()
  if (!api?.CopyInvite) {
    log('当前 exe 太旧，无法复制邀请链接。', 'warn')
    return
  }
  const generation = Number.parseInt(els.generation.value || '0', 10)
  try {
    const link = await api.CopyInvite(
      els.serverName.value.trim(),
      els.serverAddr.value.trim(),
      els.seedHex.value.trim(),
      els.pskHex.value.trim(),
      generation,
    )
    if (link) els.inviteInput.value = link
    log('邀请链接已复制。它就是密钥，不要发到公开群。', 'ok')
  } catch (e) {
    log(`复制失败：${e}`, 'error')
  }
}

els.connectBtn.addEventListener('click', () => {
  if (currentStatus === 'connected') disconnect()
  else if (currentStatus !== 'connecting') connect()
})
els.importBtn.addEventListener('click', () => importInvite())
els.copyInviteBtn.addEventListener('click', copyInvite)
els.inviteInput.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    ev.preventDefault()
    importInvite()
  }
})
els.inviteInput.addEventListener('paste', (ev) => {
  const text = ev.clipboardData?.getData('text') || ''
  if (text.includes('chimera://') || text.trim().startsWith('{')) {
    setTimeout(() => importInvite(text), 0)
  }
})
document.querySelectorAll('[data-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => toggleSecret(btn))
})
els.clearLogsBtn.addEventListener('click', clearLogs)

els.saveServerBtn.addEventListener('click', async () => {
  const api = getAPI()
  const addr = els.serverAddr.value.trim()
  if (!api) {
    log(`Wails 绑定不可用，无法保存入口（${describeGoBindings()}）。`, 'warn')
    return
  }
  if (!addr) {
    log('先填写服务器地址再保存入口。', 'warn')
    return
  }
  try {
    await api.RememberServer(els.serverName.value.trim() || addr, addr)
    await refreshServers()
    log(`已保存入口 ${addr}`)
  } catch (e) {
    log(`保存入口失败：${e}`, 'error')
  }
})
els.trayBtn.addEventListener('click', async () => {
  const api = getAPI()
  if (!api?.HideToTray) return
  log('窗口已隐藏。在托盘图标上单击可再打开。')
  await api.HideToTray()
})

;(async function init() {
  const api = await waitForAPI()
  if (!api) {
    log(`Wails 绑定不可用：${describeGoBindings()}。请运行发布包里的 ChimeraClient.exe。`, 'error')
    renderStatus('error', 'Wails binding missing')
    els.connectBtn.disabled = true
    return
  }

  await loadConfig(true)

  await refreshStatus()
  await refreshTraffic()
  setInterval(async () => {
    await refreshStatus()
    await refreshTraffic()
  }, 1000)
  window.addEventListener('resize', drawSpark)
  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(drawSpark).observe(els.spark)
  }
})()
