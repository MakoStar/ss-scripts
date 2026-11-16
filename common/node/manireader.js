const fs = require('node:fs')

class ManiResource {
  constructor(file, hash, size, fileType) {
    this.file = file
    this.hash = hash
    this.size = size
    this.fileType = fileType
  }
}

class ManiReader {
  constructor(maniPath) {
    this.maniPath = maniPath
    this.resourceData = new Map()
    this.configData = new Map()
    this.parse()
  }

  parse() {
    const content = fs.readFileSync(this.maniPath, 'utf-8')
    const lines = content.split(/\r?\n/)
    for (const rawLine of lines) {
      const line = rawLine.trim()
      if (!line) continue
      if (line.startsWith('$')) {
        const entry = line.substring(1)
        const split = entry.indexOf(':')
        if (split !== -1) {
          const key = entry.substring(0, split).trim()
          const value = entry.substring(split + 1).trim()
          this.configData.set(key, value)
        }
        continue
      }
      const parts = line.split('|')
      if (parts.length < 4) {
        console.debug(`skip malformed line: ${line}`)
        continue
      }
      const file = parts[0].trim()
      this.resourceData.set(file, new ManiResource(
        file,
        parts[1].trim(),
        parseInt(parts[2].trim(), 10) || 0,
        parts[3].trim()
      ))
    }
    console.debug(`parsed ${this.maniPath}: ${this.resourceData.size} resources, ${this.configData.size} configs`)
  }

  resources() {
    const items = Array.from(this.resourceData.values())
    items.sort((a, b) => a.file.localeCompare(b.file))
    return items
  }

  getConfigValueByKey(key) {
    if (this.configData.size === 0) {
      console.warn(`empty manifest config: ${this.maniPath}`)
      return null
    }
    const value = this.configData.get(key)
    if (value === undefined) {
      console.warn(`config key '${key}' not found in manifest`)
      return null
    }
    return value
  }
}

module.exports = { ManiReader, ManiResource }
