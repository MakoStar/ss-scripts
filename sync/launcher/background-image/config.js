import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appConfig = require("../../../config.json");

const REGION = "CN";
const regionCfg = appConfig[REGION];
const globalCfg = appConfig.GLOBAL;

const BASE_URL = regionCfg.API_URL;
const BASE_CONFIG = globalCfg.BASE_CONFIG;
const GAME_CONFIG = globalCfg.GAME_CONFIG;
const GAME_ID = regionCfg.TAG;
const CLIENT_VERSION = regionCfg.CLIENT_VERSION;
const SALT = regionCfg.SALT;

const WORK_DIR = process.env.BG_WORK_DIR || path.join(__dirname, "output");
const MD_PATH = path.join(WORK_DIR, "background.md");
const IMAGE_DIR = path.join(WORK_DIR, "image");

export {
  BASE_URL,
  BASE_CONFIG,
  GAME_CONFIG,
  GAME_ID,
  CLIENT_VERSION,
  SALT,
  REGION,
  WORK_DIR,
  MD_PATH,
  IMAGE_DIR
};
