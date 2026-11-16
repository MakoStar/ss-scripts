const path = require('node:path')
const appConfig = require('../../../config.json')

const ROOT = __dirname
const REGIONS = appConfig.REGIONS
const PLATFORMS = appConfig.PLATFORMS
const GLOBAL = appConfig.GLOBAL

const MANIFEST_DIR = process.env.MANIFEST_DIR
  ? path.resolve(process.env.MANIFEST_DIR)
  : path.join(ROOT, 'manifest')
const OUT_DIR = process.env.RESOURCE_URL_OUT_DIR
  ? path.resolve(process.env.RESOURCE_URL_OUT_DIR)
  : path.join(ROOT, 'output')

function hostOf(region) {
  return appConfig[region].STATIC_URL
}

function manifestFile(region, platform) {
  return path.join(MANIFEST_DIR, region, `${platform}_resource_manifest.json`)
}

module.exports = {
  ROOT,
  REGIONS,
  PLATFORMS,
  GLOBAL,
  MANIFEST_DIR,
  OUT_DIR,
  hostOf,
  manifestFile
}
