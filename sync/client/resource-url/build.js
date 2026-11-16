const fs = require('node:fs')
const path = require('node:path')
const {
  REGIONS,
  PLATFORMS,
  GLOBAL,
  MANIFEST_DIR,
  OUT_DIR,
  hostOf,
  manifestFile
} = require('./config')

// 渲染资源URL
function renderUrl(template, host, platform, version, ap, file) {
  return host + template
    .replace('{platform}', platform)
    .replace('{version}', version)
    .replace('{ap}', ap)
    .replace('{file}', file)
}

// 从单个平台清单聚合附加路径分组
function mergeManifest(agg, raw) {
  let obj

  try {
    obj = JSON.parse(raw)
  } catch {
    return 0
  }

  let n = 0

  for (const key of Object.keys(obj)) {
    const item = obj[key]
    if (!item) continue

    const ap = item.AdditionalPath || item.AdditionaonalPath
    const ver = parseInt(item.Version, 10)
    const file = item.FileName || key

    if (!ap || !Number.isFinite(ver) || !file) continue
    if (!/^[0-9a-f]{32}$/i.test(ap)) continue

    const groupKey = `${ver}|${ap.toLowerCase()}`
    let set = agg.get(groupKey)

    if (!set) {
      set = new Set()
      agg.set(groupKey, set)
    }

    set.add(file)
    n++
  }

  return n
}

// 构建该区域该平台的汇总行
function buildRows(agg) {
  return [...agg.entries()]
    .map(([key, set]) => {
      const [version, ap] = key.split('|')
      return { version: parseInt(version, 10), ap, files: set.size }
    })
    .sort((a, b) => a.version - b.version || a.ap.localeCompare(b.ap))
}

// 写出区域平台URL映射文件
function writeResJson(region, platform, agg, host) {
  const entries = [...agg.entries()].sort((a, b) => {
    const [av, aa] = a[0].split('|')
    const [bv, ba] = b[0].split('|')
    return parseInt(av, 10) - parseInt(bv, 10) || aa.localeCompare(ba)
  })

  const result = {}
  let count = 0

  for (const [key, set] of entries) {
    const [version, ap] = key.split('|')
    if (!result[version]) result[version] = {}
    const urls = [...set].sort().map((file) =>
      renderUrl(GLOBAL.RES_URL_TEMPLATE, host, platform, version, ap, file)
    )
    result[version][ap] = urls
    count += urls.length
  }

  const name = GLOBAL.RES_AP_FILE_TEMPLATE
    .replace('{region}', region.toLowerCase())
    .replace('{platform}', platform)
  const dir = path.join(OUT_DIR, region)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, name), JSON.stringify(result, null, 2))

  return { name, count }
}

// 写出区域附加路径汇总json
function writeApJson(region, rowsByPlatform) {
  const result = {}
  for (const platform of PLATFORMS) {
    result[platform] = rowsByPlatform[platform].map((row) => ({
      version: row.version,
      ap: row.ap,
      files: row.files
    }))
  }
  const file = path.join(OUT_DIR, region, GLOBAL.RES_AP_NAME)
  fs.writeFileSync(file, JSON.stringify(result, null, 2))
}

// 写出区域附加路径汇总md
function writeApMd(region, rowsByPlatform) {
  const blocks = []

  for (const platform of PLATFORMS) {
    const rows = rowsByPlatform[platform]
    if (!rows.length) continue
    const lines = [`## ${platform}`, '', '| version | ap | files |', '| --- | --- | --- |']
    for (const row of rows) {
      lines.push(`| ${row.version} | ${row.ap} | ${row.files} |`)
    }
    blocks.push(lines.join('\n'))
  }

  const file = path.join(OUT_DIR, region, GLOBAL.RES_AP_MD_NAME)
  fs.writeFileSync(file, blocks.join('\n\n') + '\n')
}

// 生成全部区域与平台的URL数据
function generate() {
  if (!fs.existsSync(MANIFEST_DIR)) throw new Error(`Manifest dir not found: ${MANIFEST_DIR}`)
  fs.mkdirSync(OUT_DIR, { recursive: true })

  const summary = []

  for (const region of REGIONS) {
    const host = hostOf(region)
    const rowsByPlatform = {}
    const regionStat = { region, platforms: [] }

    for (const platform of PLATFORMS) {
      const file = manifestFile(region, platform)
      if (!fs.existsSync(file)) throw new Error(`Manifest not found: ${file}`)

      const agg = new Map()
      mergeManifest(agg, fs.readFileSync(file, 'utf8'))

      const rows = buildRows(agg)
      rowsByPlatform[platform] = rows

      const written = writeResJson(region, platform, agg, host)
      regionStat.platforms.push({ platform, versions: rows.length, urls: written.count, file: written.name })
    }

    writeApJson(region, rowsByPlatform)
    writeApMd(region, rowsByPlatform)
    summary.push(regionStat)
  }

  return summary
}

// 打印生成汇总
function printSummary(summary) {
  for (const item of summary) {
    console.log(`[${item.region}]`)
    for (const p of item.platforms) {
      console.log(`  ${p.platform}: ${p.versions} versions, ${p.urls} urls -> ${p.file}`)
    }
  }
  console.log(`Output: ${OUT_DIR}`)
}

module.exports = { generate, printSummary }
