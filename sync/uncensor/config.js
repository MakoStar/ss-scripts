const path = require('node:path')
const appConfig = require('../../config.json')

const GLOBAL = appConfig.GLOBAL

const ROOT = __dirname
const MANI_URL = GLOBAL.UNCENSOR_MANI_URL
const MANI_FILE = GLOBAL.UNCENSOR_MANI_FILE
const VERSION_FILE = GLOBAL.UNCENSOR_VERSION_FILE
const MANIFEST_FILE = GLOBAL.UNCENSOR_MANIFEST_FILE

const CONFIG_KEYS = [
  'RES_VER',
  'CLIENT_VER',
  'CLIENT_VER_COMP_MODE',
  'GAME_VER',
  'CLEAR_EXPIRED_FILES'
]

const OUT_DIR = process.env.UNCENSOR_OUT_DIR
  ? path.resolve(process.env.UNCENSOR_OUT_DIR)
  : path.join(ROOT, 'manifest')

module.exports = {
  ROOT,
  MANI_URL,
  MANI_FILE,
  VERSION_FILE,
  MANIFEST_FILE,
  CONFIG_KEYS,
  OUT_DIR
}
