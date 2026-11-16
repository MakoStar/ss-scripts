const { spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')
const { EXE_PATH, OUTPUT_DIR, CACHE_DIR } = require('./config')

// 执行单区域单平台的清单导出
function fetchManifest(region, platform, opts) {
  return new Promise((resolve) => {
    const args = [
      'client',
      '-r',
      '-s', `GLOBAL.DEFAULT_REGION=${region}`,
      '-s', `GLOBAL.DEFAULT_PLATFORM=${platform}`,
      '-s', `TASK.CLIENT.FILEPATH.VERSIONS=./output/Manifest/${region}`
    ]

    const child = spawn(EXE_PATH, args, { cwd: opts.root, windowsHide: true })
    let output = ''
    let timer = null
    let settled = false

    const finish = (result) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolve({ region, platform, ...result })
    }

    child.stdout.on('data', (chunk) => {
      output += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      output += chunk.toString()
    })
    child.on('error', (err) => finish({ ok: false, output, error: err.message }))
    child.on('close', (code) => finish({ ok: code === 0, output, code }))

    timer = setTimeout(() => {
      child.kill()
      finish({ ok: false, output, error: `timeout after ${opts.timeout}ms` })
    }, opts.timeout)
  })
}

// 校验该区域平台清单文件是否落盘
function verifyArtifacts(region, platform) {
  const dir = path.join(OUTPUT_DIR, 'Manifest', region)
  const files = [
    path.join(dir, `${platform}_resource_manifest.json`),
    path.join(dir, `${platform}_patch_manifest.json`),
    path.join(dir, `${platform}_version.json`)
  ]
  const existing = files.filter((f) => fs.existsSync(f) && fs.statSync(f).size > 0)
  return { ok: existing.length === files.length, files: existing }
}

// 保存单个任务日志到缓存目录
function saveLog(result) {
  const logDir = path.join(CACHE_DIR, 'logs')
  fs.mkdirSync(logDir, { recursive: true })
  const name = `${result.region}_${result.platform}.log`
  fs.writeFileSync(path.join(logDir, name), result.output || '', 'utf8')
}

module.exports = { fetchManifest, verifyArtifacts, saveLog }
