const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const {
  REGIONS,
  API_ROUTE,
  API_PARAMS,
  VERSION_FILE,
  CONFIG_FILE,
  RETRIEVE_FILE,
  MANIFEST_FILE,
  OUT_DIR,
  endpointOf
} = require('./config')

// 复刻 Rust 签名：md5(JSON(head) + SALT)
function authHeader(endpoint) {
  const head = {
    game_tag: endpoint.TAG,
    time: Math.floor(Date.now() / 1000),
    version: endpoint.LAUNCHER_VERSION
  }
  const sign = crypto.createHash('md5').update(JSON.stringify(head) + endpoint.SALT).digest('hex')
  return JSON.stringify({ head, sign })
}

const REQUEST_TIMEOUT_MS = 30000
const MAX_RETRIES = 3

// 带鉴权头的 JSON 请求
async function getJson(url, endpoint) {
  let lastErr
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(url, {
        headers: {
          'User-Agent': 'electron-builder',
          Authorization: authHeader(endpoint)
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
      })
      if (!res.ok) throw new Error(`fetch failed ${res.status} for ${url}`)
      return await res.json()
    } catch (err) {
      lastErr = err
      if (attempt < MAX_RETRIES) {
        console.warn(`[retry ${attempt}/${MAX_RETRIES}] ${err.message} (url=${url})`)
        await new Promise((resolve) => setTimeout(resolve, 2000 * attempt))
      }
    }
  }
  throw lastErr
}

// 提取响应 data 下的指定字符串字段
function dataValue(json, key) {
  const value = json && json.data && json.data[key]
  return value == null ? '' : String(value)
}

// 写入 JSON 到区域目录
function saveJson(region, file, data) {
  const dir = path.join(OUT_DIR, region)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, file), JSON.stringify(data, null, 4), 'utf8')
}

// 处理单个区域的 launcher 配置与清单
async function processRegion(region) {
  const endpoint = endpointOf(region)
  const base = endpoint.API_URL + API_ROUTE

  const info = await getJson(base, endpoint)
  saveJson(region, CONFIG_FILE, info)

  const ver = dataValue(info, 'game_latest_version')
  const filePath = dataValue(info, 'game_latest_file_path')
  if (!ver || !filePath) throw new Error(`[${region}] missing version or file path`)

  const params = API_PARAMS.replace('{ver}', ver).replace('{path}', filePath)
  const retrieve = await getJson(base + params, endpoint)
  saveJson(region, RETRIEVE_FILE, retrieve)

  const manifestUrl = dataValue(retrieve, 'url')
  if (!manifestUrl) throw new Error(`[${region}] missing manifest url`)

  const manifest = await getJson(manifestUrl, endpoint)
  saveJson(region, MANIFEST_FILE, manifest)

  console.log(`[${region}] v${ver} ok`)
  return ver
}

// 入口：遍历全部区域生成数据并写版本汇总
async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true })
  const versions = {}
  for (const region of REGIONS) {
    versions[region] = await processRegion(region)
  }
  fs.writeFileSync(path.join(OUT_DIR, VERSION_FILE), JSON.stringify(versions, null, 4), 'utf8')
  console.log(`saved ${VERSION_FILE}, ${REGIONS.length} regions`)
}

main().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
