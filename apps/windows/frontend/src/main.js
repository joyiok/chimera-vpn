import './style.css'

// Wails v2 会把 package main 中的绑定生成到 window.go.main.App。
// 需求中约定的调用路径为 window.go.chimera.App；这里做一个轻量别名，
// 让后续代码统一使用 window.go.chimera.App。
// 注意：不在模块加载时缓存 api，避免 Wails runtime 尚未注入 window.go。
function getAPI() {
  if (!window.go) return null

  if (!window.go.chimera && window.go.main) {
    window.go.chimera = window.go.main
  }
  return window.go.chimera?.App ?? null
}

// Wails runtime 通常在页面脚本之前注入；这里做短轮询，兼容模块脚本先执行的情况。
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
  seedHex: $('seedHex'),
  generation: $('generation'),
  pskHex: $('pskHex'),
  connectBtn: $('connectBtn'),
  disconnectBtn: $('disconnectBtn'),
  defaultServerBtn: $('defaultServerBtn'),
  reloadConfigBtn: $('reloadConfigBtn'),
  logs: $('logs'),
  autoLoad: $('autoLoad'),
  autoStatus: $('autoStatus'),
}

const STATUS_TEXT = {
  disconnected: '未连接',
  connecting: '连接中',
  connected: '已连接',
  error: '错误',
}

function log(message, level = 'info') {
  const line = document.createElement('div')
  line.className = `log ${level}`
  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  line.textContent = `[${time}] ${message}`
  els.logs.appendChild(line)
  while (els.logs.children.length > 200) els.logs.firstChild.remove()
  els.logs.scrollTop = els.logs.scrollHeight
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

async function connect() {
  const api = getAPI()
  if (!api) {
    log('Wails 绑定不可用，请通过 wails dev / wails build 运行。', 'warn')
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
    log('Start 调用成功。')
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
    if (!silent) log('配置已载入。')
  } catch (e) {
    log(`读取配置失败：${e}`, 'error')
  }
}

async function fillDefaultServer() {
  const api = getAPI()
  if (!api) return
  try {
    els.serverAddr.value = await api.SelectServerDefault()
    log('已填入默认服务器地址。')
  } catch (e) {
    log(`获取默认服务器失败：${e}`, 'error')
  }
}

// 显示/隐藏密钥输入框。
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
els.defaultServerBtn.addEventListener('click', fillDefaultServer)
els.reloadConfigBtn.addEventListener('click', () => loadConfig(false))

// 启动流程：优先载入已保存配置，然后默认服务器兜底，再刷新状态。
;(async function init() {
  const api = await waitForAPI()
  if (!api) {
    log('Wails 绑定不可用：请使用 wails dev 或 wails build 运行本应用。', 'error')
    updateBadge('error', 'Wails binding missing')
    return
  }

  if (els.autoLoad.checked) {
    await loadConfig(true)
  }
  if (!els.serverAddr.value) {
    await fillDefaultServer()
  }

  await refreshStatus()
  setInterval(async () => {
    if (els.autoStatus.checked) await refreshStatus()
  }, 2000)
})()
