const path = require('node:path')
const appConfig = require('../../../config.json')

const ROOT = __dirname
const WORK_DIR = process.env.MANIFEST_WORK_DIR || ROOT
const EXE_PATH = process.env.RESOURCE_FETCHER_EXE || path.join(ROOT, 'tool', 'ResourceFetcher.exe')
const OUTPUT_DIR = path.join(WORK_DIR, 'output')
const CACHE_DIR = path.join(ROOT, 'tests', '.cache')

const REGIONS = appConfig.REGIONS
const PLATFORMS = appConfig.PLATFORMS
const CONCURRENCY = 2
const TIMEOUT_MS = 180000

// 读取并解析命令行参数
function parseArgs(argv) {
  const opts = {
    regions: REGIONS,
    platforms: PLATFORMS,
    concurrency: CONCURRENCY,
    timeout: TIMEOUT_MS,
    root: WORK_DIR,
    help: false
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      opts.help = true
    } else if (arg === '--regions' && argv[i + 1]) {
      opts.regions = argv[++i].split(',').map((s) => s.trim().toUpperCase()).filter(Boolean)
    } else if (arg === '--platforms' && argv[i + 1]) {
      opts.platforms = argv[++i].split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    } else if (arg === '--concurrency' && argv[i + 1]) {
      const n = Number(argv[++i])
      if (Number.isInteger(n) && n > 0) opts.concurrency = n
    } else if (arg === '--timeout' && argv[i + 1]) {
      const n = Number(argv[++i])
      if (Number.isFinite(n) && n > 0) opts.timeout = n * 1000
    }
  }

  return opts
}

module.exports = {
  ROOT,
  WORK_DIR,
  EXE_PATH,
  OUTPUT_DIR,
  CACHE_DIR,
  REGIONS,
  PLATFORMS,
  parseArgs
}
