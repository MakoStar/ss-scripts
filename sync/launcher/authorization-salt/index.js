const fs = require('node:fs')
const path = require('node:path')
const axios = require('axios')
const fse = require('fs-extra')
const yaml = require('js-yaml')
const asar = require('@electron/asar')
const { path7za } = require('7zip-bin')
const { execFile } = require('node:child_process')
const {
  REGIONS,
  OUT_DIR,
  DATA_DIR,
  LATEST_YML,
  SALT_FILE,
  endpointOf
} = require('./config')

try {
  fs.chmodSync(path7za, 0o755)
} catch (err) {
  console.warn('⚠️ Cannot set 7za permission, continue anyway')
}

const MAX_RETRIES = 3
const RETRY_BASE_MS = 2000
const API_TIMEOUT_MS = 6e4
const PROGRESS_STEP_MS = 2000

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function logRegionHeader(region) {
  const title = ` REGION ${region} `
  const side = Math.max(0, Math.floor((64 - title.length) / 2))
  const line = '='.repeat(side)
  console.log(`\n${line}${title}${line}`)
}

async function withRetry(label, fn) {
  let lastErr
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt += 1) {
    try {
      return await fn()
    } catch (err) {
      lastErr = err
      if (attempt < MAX_RETRIES) {
        const delay = RETRY_BASE_MS * attempt
        console.warn(`⚠️ [retry ${attempt}/${MAX_RETRIES}] ${label} failed: ${err.message} (wait ${delay}ms)`)
        await sleep(delay)
      }
    }
  }
  throw lastErr
}

function buildUrl(base, ...segments) {
  let url = new URL(base)
  for (const seg of segments) {
    if (!seg) continue
    if (!url.pathname.endsWith('/')) url.pathname += '/'
    url = new URL(seg.replace(/^\/+/, ''), url)
  }
  return url.href
}

const createRegionAxiosClient = (region) => {
  const config = endpointOf(region)
  if (!config) throw new Error(`unknown region: ${region}`)

  const client = axios.create({
    timeout: API_TIMEOUT_MS,
    baseURL: config.API_URL,
    withCredentials: true,
    headers: { 'Content-Type': 'application/json;charset=UTF-8' }
  })

  client.interceptors.request.use(async (cfg) => {
    if (cfg._isDownload) {
      cfg.headers = new axios.AxiosHeaders({ 'Cache-Control': 'no-cache' })
      cfg.baseURL = ''
      cfg.withCredentials = false
    }
    return cfg
  })

  client.interceptors.response.use(
    (res) => res.data,
    (err) => Promise.reject(err)
  )

  return client
}

const axiosCache = {}
const getRegionAxiosClient = (region) => {
  if (!axiosCache[region]) axiosCache[region] = createRegionAxiosClient(region)
  return axiosCache[region]
}

const downloader = async (targetUrl, destPath) => {
  await fse.ensureDir(path.dirname(destPath))
  const tmpPath = `${destPath}.tmp`

  let resumeFrom = 0
  if (await fse.pathExists(tmpPath)) {
    resumeFrom = (await fse.stat(tmpPath)).size
  }

  const headers = resumeFrom > 0 ? { Range: `bytes=${resumeFrom}-` } : {}
  const response = await axios.get(targetUrl, {
    responseType: 'stream',
    timeout: API_TIMEOUT_MS,
    headers
  })

  const total = Number(response.headers['content-length'] || 0) + resumeFrom
  const isRange = response.status === 206
  if (resumeFrom > 0 && !isRange) {
    resumeFrom = 0
  }

  const writer = fs.createWriteStream(tmpPath, { flags: isRange && resumeFrom > 0 ? 'a' : 'w' })
  let downloaded = resumeFrom
  let lastPrint = Date.now()
  let lastBytes = resumeFrom

  try {
    await new Promise((resolve, reject) => {
      response.data.on('data', (chunk) => {
        downloaded += chunk.length
        const now = Date.now()
        if (now - lastPrint >= PROGRESS_STEP_MS) {
          const speed = (downloaded - lastBytes) / ((now - lastPrint) / 1000)
          const pct = total ? ((downloaded / total) * 100).toFixed(1) : '?'
          console.log(`  ⬇️ ${pct}% (${formatBytes(downloaded)}/${formatBytes(total)}) ${formatBytes(speed)}/s`)
          lastPrint = now
          lastBytes = downloaded
        }
      })
      response.data.on('error', reject)
      writer.on('error', reject)
      writer.on('finish', resolve)
      response.data.pipe(writer)
    })
    await fse.move(tmpPath, destPath, { overwrite: true })
    console.log(`✅ download ok: ${destPath} (${formatBytes(downloaded)})`)
  } catch (err) {
    console.error(`❌ download failed: ${err.message}`)
    throw err
  }
}

const run7z = async (args) => new Promise((resolve, reject) => {
  execFile(path7za, args, (error, stdout, stderr) => {
    if (error) reject(new Error(`7z failed: ${stderr || error.message}`))
    else resolve(stdout)
  })
})

const extractWith7z = (exePath, outputDir) =>
  run7z(['x', '-t#', exePath, `-o${outputDir}`, '-y'])

const findAndExtract7z = async (sourceDir, targetDir) => {
  const files = await fse.readdir(sourceDir)
  const sevenZFiles = files.filter((f) => f.endsWith('.7z') && /^\d+\.7z$/.test(f))
  if (sevenZFiles.length === 0) throw new Error('no numbered .7z files found')

  const stats = await Promise.all(
    sevenZFiles.map(async (f) => ({
      name: f,
      size: (await fse.stat(path.join(sourceDir, f))).size
    }))
  )
  const target = stats.sort((a, b) => b.size - a.size)[0]
  console.log(`📦 target 7z: ${target.name} (${(target.size / 1024 / 1024).toFixed(1)} MB)`)
  return run7z(['x', '-t7z', path.join(sourceDir, target.name), `-o${targetDir}`, '-aoa', '-y'])
}

const cleanTemp = async (sourceDir) => {
  const entries = await fse.readdir(sourceDir, { withFileTypes: true })
  for (const entry of entries) {
    if (entry.isFile() && !entry.name.endsWith('.7z')) {
      await fse.remove(path.join(sourceDir, entry.name))
    }
  }
}

const extractSaltFromFile = (filePath) => {
  const content = fse.readFileSync(filePath, 'utf8')
  const match = content.match(/salt\s*:\s*[""]([^""]+)["']/)
  if (!match) throw new Error(`salt not found in: ${filePath}`)
  return match[1]
}

async function processRegion(region) {
  const { TAG, PKG_URL, PKG_ROUTE } = endpointOf(region)
  logRegionHeader(region)

  const pkgBaseUrl = buildUrl(PKG_URL, PKG_ROUTE, TAG)
  const retrieveUrl = buildUrl(pkgBaseUrl, LATEST_YML)

  console.log(`⬇️ fetching: ${retrieveUrl}`)
  const ymlContent = await withRetry(`fetch ${LATEST_YML} for ${region}`, () =>
    getRegionAxiosClient(region).get(retrieveUrl, { _isDownload: true })
  )
  const latestConfig = yaml.load(ymlContent, { schema: yaml.FAILSAFE_SCHEMA })
  const regionOutputDir = path.join(OUT_DIR, region)
  await fse.outputFile(path.join(regionOutputDir, LATEST_YML), ymlContent)

  const targetLauncherPath = latestConfig?.path
  const launcherVersion = latestConfig?.version
  if (!targetLauncherPath) throw new Error(`latest.yml missing "path" for ${region}`)

  const launcherUrl = buildUrl(pkgBaseUrl, targetLauncherPath)
  const storageDir = path.join(DATA_DIR, region)
  const launcherDest = path.join(storageDir, path.basename(targetLauncherPath))

  console.log(`⬇️ downloading launcher: ${launcherUrl}`)
  await withRetry(`download launcher for ${region}`, () =>
    downloader(launcherUrl, launcherDest)
  )

  const tempDir = path.join(storageDir, 'temp')
  const finalDir = path.join(storageDir, 'final')
  await fse.ensureDir(tempDir)
  await fse.ensureDir(finalDir)

  console.log('📂 extracting installer')
  await withRetry(`extract installer for ${region}`, () =>
    extractWith7z(launcherDest, tempDir)
  )

  console.log('📂 extracting game assets')
  await withRetry(`extract assets for ${region}`, () =>
    findAndExtract7z(tempDir, finalDir)
  )

  console.log('🧹 cleaning temp files')
  await cleanTemp(tempDir)

  const asarPath = path.join(finalDir, 'resources', 'app.asar')
  const asarOutDir = path.join(finalDir, 'source')
  if (!(await fse.pathExists(asarPath))) {
    throw new Error(`app.asar not found at: ${asarPath}`)
  }

  console.log('📦 extracting app.asar')
  await withRetry(`extract asar for ${region}`, () =>
    asar.extractAll(asarPath, asarOutDir)
  )

  const saltFilePath = path.join(asarOutDir, 'out', 'main', 'index.js')
  const salt = extractSaltFromFile(saltFilePath)

  console.log(`🔑 salt ${region}: ${salt}`)
  return { salt, ver: launcherVersion }
}

;(async () => {
  const saltData = {}
  for (const region of REGIONS) {
    saltData[region] = await processRegion(region)
  }

  console.log('\n✅ all regions processed successfully')
  await fse.outputFile(
    path.join(OUT_DIR, SALT_FILE),
    JSON.stringify(saltData, null, 4),
    { encoding: 'utf-8' }
  )
})().catch((err) => {
  console.error('💥 fatal error:', err)
  process.exit(1)
})
