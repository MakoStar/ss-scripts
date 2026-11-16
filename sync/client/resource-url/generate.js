const fs = require('node:fs')
const path = require('node:path')
const { REGIONS, PLATFORMS, GLOBAL, OUT_DIR } = require('./config')
const { generate, printSummary } = require('./build')

// 校验全部产物已生成且非空
function verify() {
  for (const region of REGIONS) {
    const dir = path.join(OUT_DIR, region)
    const files = [
      path.join(dir, GLOBAL.RES_AP_NAME),
      path.join(dir, GLOBAL.RES_AP_MD_NAME)
    ]
    for (const platform of PLATFORMS) {
      const name = GLOBAL.RES_AP_FILE_TEMPLATE
        .replace('{region}', region.toLowerCase())
        .replace('{platform}', platform)
      files.push(path.join(dir, name))
    }

    for (const file of files) {
      if (!fs.existsSync(file)) throw new Error(`Missing output: ${file}`)
      if (fs.statSync(file).size === 0) throw new Error(`Empty output: ${file}`)
    }
  }
  console.log(`Verified ${REGIONS.length * (PLATFORMS.length + 2)} output files`)
}

// 程序入口
function main() {
  const started = Date.now()
  printSummary(generate())
  verify()
  console.log(`Finished in ${((Date.now() - started) / 1000).toFixed(1)}s`)
}

try {
  main()
} catch (e) {
  console.error(e.message)
  process.exit(1)
}
