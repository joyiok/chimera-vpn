import { defineConfig } from 'vite'

// Wails v2 会读取 frontend/dist 作为嵌入资源。
// 保持默认 outDir，构建后产物直接进入 dist。
export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
