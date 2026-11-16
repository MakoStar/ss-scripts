const fs = require('node:fs')
const path = require('node:path')
const http = require('node:http')
const https = require('node:https')
const { ManiReader } = require('../../common/node/manireader')
const {
  MANI_URL,
  MANI_FILE,
  VERSION_FILE,
  MANIFEST_FILE,
  CONFIG_KEYS,
  OUT_DIR
} = require('./config')

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true })
    console.log(`created dir ${dirPath}`)
  }
}

function downloadFile(url, filePath) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http
    const fileStream = fs.createWriteStream(filePath)

    const handle = (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        console.log(`redirect -> ${response.headers.location}`)
        client.get(response.headers.location, handle).on('error', reject)
        return
      }
      if (response.statusCode !== 200) {
        reject(new Error(`download failed ${response.statusCode}: ${url}`))
        return
      }
      response.pipe(fileStream)
      fileStream.on('finish', () => {
        fileStream.close()
        resolve()
      })
    }

    client.get(url, handle).on('error', (err) => {
      fileStream.close()
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
      reject(err)
    })
  })
}

function extractVersionData(reader) {
  const data = {}
  for (const key of CONFIG_KEYS) {
    const value = reader.getConfigValueByKey(key)
    if (value !== null) data[key] = value
  }
  return data
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8')
  console.log(`wrote ${filePath}`)
}

function generateManifest(reader, filePath) {
  const meta = extractVersionData(reader)
  const data = {}
  for (const res of reader.resources()) {
    data[res.hash] = res.file
  }
  meta.len = Object.keys(data).length
  writeJson(filePath, { meta, data })
}

;(async () => {
  try {
    ensureDir(OUT_DIR)
    const maniPath = path.join(OUT_DIR, MANI_FILE)

    console.log(`downloading ${MANI_URL}`)
    await downloadFile(MANI_URL, maniPath)
    console.log(`saved ${maniPath}`)

    const reader = new ManiReader(maniPath)
    writeJson(path.join(OUT_DIR, VERSION_FILE), extractVersionData(reader))
    generateManifest(reader, path.join(OUT_DIR, MANIFEST_FILE))

    console.log('done')
  } catch (err) {
    console.error(`failed: ${err.message}`)
    process.exit(1)
  }
})()
