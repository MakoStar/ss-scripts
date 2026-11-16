const fs = require('node:fs')
const { EXE_PATH, OUTPUT_DIR, parseArgs } = require('./config')
const { runAll, saveSummary } = require('./runner')

// 打印使用说明
function printHelp() {
  console.log(`
用法: node index.js [选项]

批量导出 StellaSora 全部区域的客户端资源清单。
调用 tool/ResourceFetcher.exe 的 client -r 模式，
按区域与平台组合逐个导出，结果落在 output/Manifest/<区域>/。

选项:
  --regions CN,EN,JP,KR,TW   指定区域，逗号分隔，默认全部
  --platforms win,and,ios    指定平台，逗号分隔，默认全部
  --concurrency N            并发任务数，默认 2
  --timeout N                单任务超时秒数，默认 180
  -h, --help                 显示帮助

示例:
  node index.js
  node index.js --regions CN,JP --platforms win
  node index.js --concurrency 3 --timeout 240
`)
}

// 程序入口
async function main() {
  const opts = parseArgs(process.argv.slice(2))

  if (opts.help) {
    printHelp()
    return
  }

  if (!fs.existsSync(EXE_PATH)) {
    console.error(`找不到工具: ${EXE_PATH}`)
    process.exitCode = 1
    return
  }

  const total = opts.regions.length * opts.platforms.length
  console.log(`开始导出 ${total} 组清单`)
  console.log(`区域: ${opts.regions.join(', ')}`)
  console.log(`平台: ${opts.platforms.join(', ')}`)
  console.log(`并发: ${opts.concurrency}\n`)

  const started = Date.now()
  const results = await runAll(opts.regions, opts.platforms, opts)
  const failed = results.filter((r) => !r.ok || !r.verified.ok)
  const seconds = ((Date.now() - started) / 1000).toFixed(1)
  const summaryFile = saveSummary(results)

  console.log(`\n完成 ${results.length - failed.length}/${results.length} 组，用时 ${seconds}s`)
  console.log(`清单目录: ${OUTPUT_DIR}/Manifest`)
  console.log(`汇总报告: ${summaryFile}`)

  if (failed.length) {
    console.log(`失败组合: ${failed.map((r) => `${r.region}/${r.platform}`).join(', ')}`)
    process.exitCode = 1
  }
}

main().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
