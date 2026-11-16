const fs = require('node:fs')
const { EXE_PATH, OUTPUT_DIR, parseArgs } = require('./config')
const { runAll, saveSummary } = require('./runner')

// print usage
function printHelp() {
  console.log(`
Usage: node index.js [options]

Export client resource manifests for all regions and platforms.
Uses ResourceFetcher client -r mode, iterating region x platform,
output to output/Manifest/<region>/.

Options:
  --regions CN,EN,JP,KR,TW   comma-separated regions, default all
  --platforms win,and,ios    comma-separated platforms, default all
  --concurrency N            parallel tasks, default 2
  --timeout N                per-task timeout in seconds, default 180
  -h, --help                 show this help

Examples:
  node index.js
  node index.js --regions CN,JP --platforms win
  node index.js --concurrency 3 --timeout 240
`)
}

// entry point
async function main() {
  const opts = parseArgs(process.argv.slice(2))

  if (opts.help) {
    printHelp()
    return
  }

  if (!fs.existsSync(EXE_PATH)) {
    console.error(`Tool not found: ${EXE_PATH}`)
    process.exitCode = 1
    return
  }

  const total = opts.regions.length * opts.platforms.length
  console.log(`Exporting ${total} manifest sets`)
  console.log(`Regions: ${opts.regions.join(', ')}`)
  console.log(`Platforms: ${opts.platforms.join(', ')}`)
  console.log(`Concurrency: ${opts.concurrency}\n`)

  const started = Date.now()
  const results = await runAll(opts.regions, opts.platforms, opts)
  const failed = results.filter((r) => !r.ok || !r.verified.ok)
  const seconds = ((Date.now() - started) / 1000).toFixed(1)
  const summaryFile = saveSummary(results)

  console.log(`\nDone ${results.length - failed.length}/${results.length} sets in ${seconds}s`)
  console.log(`Manifest dir: ${OUTPUT_DIR}/Manifest`)
  console.log(`Summary: ${summaryFile}`)

  if (failed.length) {
    console.log(`Failed: ${failed.map((r) => `${r.region}/${r.platform}`).join(', ')}`)
    process.exitCode = 1
  }
}

main().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
