const fs = require('node:fs')
const path = require('node:path')
const { fetchManifest, verifyArtifacts, saveLog } = require('./fetcher')
const { CACHE_DIR } = require('./config')

const RETRY = 2

// run a single task with retries
async function runTask(region, platform, opts) {
  let last = null

  for (let attempt = 1; attempt <= RETRY + 1; attempt++) {
    const result = await fetchManifest(region, platform, opts)
    const verified = verifyArtifacts(region, platform)
    last = { ...result, attempt, verified }

    if (result.ok && verified.ok) return last
    if (attempt <= RETRY) {
      console.log(`  [${region}/${platform}] attempt ${attempt} failed, retrying...`)
    }
  }

  return last
}

// schedule all tasks under a concurrency limit
async function runAll(regions, platforms, opts) {
  const tasks = []
  for (const region of regions) {
    for (const platform of platforms) {
      tasks.push({ region, platform })
    }
  }

  const results = new Array(tasks.length)
  let cursor = 0

  async function worker() {
    while (cursor < tasks.length) {
      const index = cursor++
      const task = tasks[index]
      process.stdout.write(`-> export ${task.region}/${task.platform} ... `)
      const result = await runTask(task.region, task.platform, opts)
      results[index] = result
      saveLog(result)
      const status = result.ok && result.verified.ok ? 'done' : 'failed'
      console.log(status)
    }
  }

  const size = Math.min(opts.concurrency, tasks.length)
  const workers = Array.from({ length: size }, () => worker())
  await Promise.all(workers)

  return results
}

// write summary to the cache directory
function saveSummary(results) {
  const dir = path.join(CACHE_DIR, 'reports')
  fs.mkdirSync(dir, { recursive: true })
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const file = path.join(dir, `summary_${stamp}.json`)
  const data = results.map((r) => ({
    region: r.region,
    platform: r.platform,
    ok: r.ok && r.verified.ok,
    code: r.code,
    attempt: r.attempt,
    error: r.error || null,
    files: r.verified.files
  }))
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8')
  return file
}

module.exports = { runAll, saveSummary }
