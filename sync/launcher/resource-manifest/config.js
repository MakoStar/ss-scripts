const path = require('node:path')
const appConfig = require('../../../config.json')

const ROOT = __dirname
const REGIONS = appConfig.REGIONS
const GLOBAL = appConfig.GLOBAL

const API_ROUTE = GLOBAL.GAME_CONFIG
const API_PARAMS = GLOBAL.LAUNCHER_API_PARAMS
const VERSION_FILE = GLOBAL.LAUNCHER_VERSION_FILE
const CONFIG_FILE = GLOBAL.LAUNCHER_CONFIG_FILE
const RETRIEVE_FILE = GLOBAL.LAUNCHER_RETRIEVE_FILE
const MANIFEST_FILE = GLOBAL.LAUNCHER_MANIFEST_FILE

const OUT_DIR = process.env.LAUNCHER_OUT_DIR
  ? path.resolve(process.env.LAUNCHER_OUT_DIR)
  : path.join(ROOT, 'output')

function endpointOf(region) {
  return appConfig[region]
}

module.exports = {
  ROOT,
  REGIONS,
  API_ROUTE,
  API_PARAMS,
  VERSION_FILE,
  CONFIG_FILE,
  RETRIEVE_FILE,
  MANIFEST_FILE,
  OUT_DIR,
  endpointOf
}
