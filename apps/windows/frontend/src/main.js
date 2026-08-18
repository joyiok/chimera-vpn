import './style.css'

function looksLikeApp(obj) {
  return !!obj && typeof obj.Start === 'function' && typeof obj.Status === 'function'
}

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
  serverAddr: $('serverAddr'),
  serverName: $('serverName'),
  seedHex: $('seedHex'),
  generation: $('generation'),
  pskHex: $('pskHex'),
  connectBtn: $('connectBtn'),
  disconnectBtn: $('disconnectBtn'),
  saveServerBtn: $('saveServerBtn'),
  trayBtn: $('trayBtn'),
  logs: $('logs'),
  serverList: $('serverList'),
  txTotal: $('txTotal'),
  rxTotal: $('rxTotal'),
  txRate: $('txRate'),
  rxRate: $('rxRate'),
  spark: $('spark'),
}

const STATUS_TEXT = {
  disconnected: '未连接',
  connecting: '连接中',
  connected: '已连接',
  error: '错误',
}

const samples = []
let lastSent = 0
let lastRecv = 0
let lastTs = 0

function log(message, level = 'info') {
  const line = document.createElement('div')
  line.className = `log ${level}`
  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  line.textContent = `[${time}] ${message}`
  els.logs.appendChild(line)
  while (els.logs.children.length > 200) els.logs.firstChild.remove()
  els.logs.scrollTop = els.logs.scrollHeight
}

function formatBytes(n) {
  const v = Number(n) || 0
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  if (v < 1024 * 1024 * 1024) return `${(v / 1024 / 1024).toFixed(2)} MB`
  return `${(v / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function updateBadge(status, detail = '') {
  const normalized = status === 'error' ? 'error' : status
  els.statusBadge.className = `badge ${normalized}`
  els.statusBadge.textContent = detail
    ? `${STATUS_TEXT[normalized] ?? normalized}：${detail}`
    : (STATUS_TEXT[normalized] ?? normalized)
}

async function refreshStatus() {
  const api = getAPI()
  if (!api) return
  try {
    const raw = await api.Status()
    const [status, ...rest] = raw.split(':')
    const detail = rest.join(':').trim()
    updateBadge(status.trim(), detail)
    return status.trim()
  } catch (e) {
    updateBadge('error', String(e))
    return 'error'
  }
}

function setBusy(busy) {
  els.connectBtn.disabled = busy
}

function drawSpark() {
  const canvas = els.spark
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  const dpr = window.devicePixelRatio || 1
  const w = canvas.clientWidth
  const h = canvas.clientHeight
  canvas.width = Math.max(1, Math.floor(w * dpr))
  canvas.height = Math.max(1, Math.floor(h * dpr))
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)
  ctx.strokeStyle = '#30363d'
  ctx.beginPath()
  ctx.moveTo(0, h - 0.5)
  ctx.lineTo(w, h - 0.5)
  ctx.stroke()
  if (samples.length < 2) return
  const max = Math.max(1, ...samples)
  ctx.strokeStyle = '#388bfd'
  ctx.lineWidth = 1.5
  ctx.beginPath()
  samples.forEach((v, i) => {
    const x = (i / (samples.length - 1)) * w
    const y = h - (v / max) * (h - 6) - 3
    if (i === 0) ctx.moveTo(x, y)
    else ctx.lineTo(x, y)
  })
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
    // stub build has Traffic but zeros
  }
}

function renderServers(list) {
  const items = Array.isArray(list) ? list : []
  if (!items.length) {
    els.serverList.innerHTML = '<div class="muted">还没有保存的入口。连上一次，或点「保存入口」。</div>'
    return
  }
  els.serverList.innerHTML = ''
  for (const s of items) {
    const row = document.createElement('div')
    row.className = 'server-row'
    const pick = document.createElement('button')
    pick.type = 'button'
    pick.className = 'pick'
    pick.innerHTML = `<strong>${escapeHtml(s.name || s.Name || s.addr)}</strong><span class="addr">${escapeHtml(s.addr || s.Addr)}</span>`
    pick.addEventListener('click', () => {
      els.serverAddr.value = s.addr || s.Addr || ''
      els.serverName.value = s.name || s.Name || ''
      log(`已选用入口 ${els.serverAddr.value}`)
    })
    const del = document.createElement('button')
    del.type = 'button'
    del.className = 'ghost'
    del.textContent = '删除'
    del.addEventListener('click', async () => {
      const api = getAPI()
      if (!api) return
      await api.ForgetServer(s.addr || s.Addr)
      await refreshServers()
    })
    row.append(pick, del)
    els.serverList.append(row)
  }
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

async function refreshServers() {
  const api = getAPI()
  if (!api?.Servers) return
  try {
    renderServers(await api.Servers())
  } catch (e) {
    log(`读取节点失败：${e}`, 'error')
  }
}

async function connect() {
  const api = getAPI()
  if (!api) {
    log(`Wails 绑定不可用，无法连接（${describeGoBindings()}）。`, 'warn')
    return
  }

  const serverAddr = els.serverAddr.value.trim()
  const seedHex = els.seedHex.value.trim()
  const pskHex = els.pskHex.value.trim()
  const generation = Number.parseInt(els.generation.value || '0', 10)

  if (!serverAddr || !seedHex || !pskHex) {
    log('请完整填写服务器地址、Seed 和 PSK。', 'warn')
    return
  }
  if (!Number.isInteger(generation) || generation < 0) {
    log('Generation 必须是非负整数。', 'warn')
    return
  }

  setBusy(true)
  log(`正在连接：server=${serverAddr} generation=${generation}`)
  try {
    await api.Start(seedHex, generation, pskHex, serverAddr)
    const name = els.serverName.value.trim()
    if (name) await api.RememberServer(name, serverAddr)
    log('Start 调用成功。')
    lastSent = 0
    lastRecv = 0
    lastTs = 0
    samples.length = 0
    await refreshServers()
  } catch (e) {
    log(`Start 调用失败：${e}`, 'error')
  } finally {
    setBusy(false)
    await refreshStatus()
  }
}

async function disconnect() {
  const api = getAPI()
  if (!api) return
  setBusy(true)
  log('正在断开连接…')
  try {
    await api.Stop()
    log('Stop 调用成功。')
  } catch (e) {
    log(`Stop 调用失败：${e}`, 'error')
  } finally {
    setBusy(false)
    await refreshStatus()
  }
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
    renderServers(cfg.servers || [])
    if (!silent) log('配置已载入。')
  } catch (e) {
    log(`读取配置失败：${e}`, 'error')
  }
}

document.querySelectorAll('[data-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.toggle)
    if (!input) return
    const isPassword = input.type === 'password'
    input.type = isPassword ? 'text' : 'password'
    btn.textContent = isPassword ? '隐藏' : '显示'
  })
})

els.connectBtn.addEventListener('click', connect)
els.disconnectBtn.addEventListener('click', disconnect)
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
  await api.RememberServer(els.serverName.value.trim() || addr, addr)
  await refreshServers()
  log(`已保存入口 ${addr}`)
})
els.trayBtn.addEventListener('click', async () => {
  const api = getAPI()
  if (!api?.HideToTray) return
  log('窗口已隐藏，在托盘图标上单击可再打开。')
  await api.HideToTray()
})

;(async function init() {
  const api = await waitForAPI()
  if (!api) {
    log(`Wails 绑定不可用：${describeGoBindings()}。请运行发布包里的 ChimeraClient.exe。`, 'error')
    updateBadge('error', 'Wails binding missing')
    return
  }

  await loadConfig(true)
  if (!els.serverAddr.value) {
    try {
      els.serverAddr.value = await api.SelectServerDefault()
    } catch {
      /* keep empty */
    }
  }

  await refreshStatus()
  await refreshTraffic()
  setInterval(async () => {
    await refreshStatus()
    await refreshTraffic()
  }, 1000)
  window.addEventListener('resize', drawSpark)
})()
