const path = require('node:path')
const appConfig = require('../../../config.json')

const ROOT = __dirname
const REGIONS = appConfig.REGIONS

const OUT_DIR = process.env.SALT_OUT_DIR
  ? path.resolve(process.env.SALT_OUT_DIR)
  : path.join(ROOT, 'output')
const DATA_DIR = process.env.SALT_DATA_DIR
  ? path.resolve(process.env.SALT_DATA_DIR)
  : path.join(ROOT, 'data_storage')

const LATEST_YML = 'latest.yml'
const SALT_FILE = 'launcher_salt.json'

function endpointOf(region) {
  return appConfig[region]
}

module.exports = {
  ROOT,
  REGIONS,
  OUT_DIR,
  DATA_DIR,
  LATEST_YML,
  SALT_FILE,
  endpointOf
}
