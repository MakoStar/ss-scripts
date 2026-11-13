#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MD_PATH = path.join(__dirname, "backgound.md");

const BASE_URL = "https://launcher-api.yostar.net";
const BASE_CONFIG = "/api/launcher/base/config";
const GAME_CONFIG = "/api/launcher/game/config";
const GAME_ID = "StellaSora_CN";
const CLIENT_VERSION = "1.3.0";
const SALT = "872550AD59A235662C5B7D5F88CEBE4B";

const DEFAULT_INTRO = `# StellaSora_CN 启动器背景图记录

> 自动抓取自 \`${BASE_URL}${BASE_CONFIG}\` 的 \`launcher_background_img\` 字段。`;

/** 构造启动器接口签名鉴权头 */
const getAuthHeader = () => {
  const head = { game_tag: GAME_ID, time: Math.floor(Date.now() / 1000), version: CLIENT_VERSION };
  const sign = crypto.createHash("md5").update(JSON.stringify(head) + SALT).digest("hex");
  return JSON.stringify({ head, sign });
};

/** 获取背景图链接与crc64 */
const fetchBackground = async () => {
  const res = await fetch(BASE_URL + BASE_CONFIG, {
    method: "GET",
    headers: { "Content-Type": "application/json;charset=UTF-8", Authorization: getAuthHeader() },
  });
  const json = await res.json();
  if (json.code !== 200) throw new Error(`base config error code=${json.code}`);
  const d = json.data || {};
  return { url: d.launcher_background_img || "", crc64: String(d.launcher_background_img_crc64 ?? "") };
};

/** 从游戏配置接口取最新游戏版本 仅作兜底 */
const fetchGameVersion = async () => {
  try {
    const res = await fetch(BASE_URL + GAME_CONFIG, {
      method: "GET",
      headers: { "Content-Type": "application/json;charset=UTF-8", Authorization: getAuthHeader() },
    });
    const json = await res.json();
    if (json.code !== 200) return "";
    return String(json.data?.game_latest_version ?? "");
  } catch {
    return "";
  }
};

/** 从ss_win.mani读取游戏版本 */
const readGameVersionFromMani = (filePath) => {
  try {
    const text = fs.readFileSync(filePath, "utf8");
    const m = text.match(/^\$GAME_VER:\s*(.+?)\s*$/m);
    return m ? m[1] : "";
  } catch {
    return "";
  }
};

/** 解析游戏版本 优先环境变量 其次mani文件 兜底接口 */
const resolveGameVersion = async () => {
  const fromEnv = process.env.GAME_VERSION?.trim();
  if (fromEnv) return fromEnv;
  const mani = process.env.MANI_PATH?.trim();
  if (mani) {
    const fromMani = readGameVersionFromMani(mani);
    if (fromMani) return fromMani;
  }
  const fromApi = await fetchGameVersion();
  if (fromApi) console.log(`[fetch-bg] warning: MANI_PATH not used, fallback to api version v${fromApi}`);
  return fromApi;
};

/** 解析已有markdown的简介与历史记录 */
const parseMd = (md) => {
  const intro = (md.split(/^## 当前背景图/m)[0] || "").trimEnd();
  const entries = [];
  const re = /^\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([\d-]+)\s*\|\s*(\d{6,})\s*\|\s*(https?:\/\/\S+?)\s*\|\s*$/gm;
  let m;
  while ((m = re.exec(md))) {
    entries.push({ num: Number(m[1]), ver: m[2].trim(), date: m[3].trim(), crc64: m[4].trim(), link: m[5].trim() });
  }
  return { intro, entries };
};

/** 按项目格式渲染markdown */
const buildMarkdown = (intro, currentUrl, entries) => {
  const sorted = entries.slice().sort((a, b) => b.num - a.num);
  const rows = sorted.map((e) => `| ${e.num} | ${e.ver} | ${e.date} | ${e.crc64} | ${e.link} |`).join("\n");
  const head = intro || DEFAULT_INTRO;
  return (
    head +
    "\n\n## 当前背景图\n" +
    `![当前背景图](${currentUrl})\n\n` +
    "## 历史记录\n\n" +
    "| # | ver | date | crc64 | link |\n" +
    "| --- | --- | --- | --- | --- |\n" +
    rows +
    "\n"
  );
};

/** 拉取背景并写入md 返回是否有新增 */
const run = async () => {
  const bg = await fetchBackground();
  if (!bg.url || !bg.crc64) throw new Error("no background image link fetched");
  const gameVer = await resolveGameVersion();

  const today = new Date().toISOString().slice(0, 10);
  let intro = DEFAULT_INTRO;
  let entries = [];
  if (fs.existsSync(MD_PATH)) {
    const parsed = parseMd(fs.readFileSync(MD_PATH, "utf8"));
    intro = parsed.intro || DEFAULT_INTRO;
    entries = parsed.entries;
  }

  console.log(`[fetch-bg] background crc64=${bg.crc64}`);
  console.log(`[fetch-bg] game latest version=v${gameVer || "?"}`);

  const known = entries.find((e) => e.crc64 === bg.crc64);
  if (known) {
    console.log(`[fetch-bg] unchanged (crc64=${bg.crc64}), skip`);
    return false;
  }

  const maxNum = entries.reduce((mx, e) => Math.max(mx, e.num), -1);
  const entry = { num: maxNum + 1, ver: gameVer ? `v${gameVer}` : "", date: today, crc64: bg.crc64, link: bg.url };
  entries.push(entry);
  fs.writeFileSync(MD_PATH, buildMarkdown(intro, bg.url, entries));
  console.log(`[fetch-bg] new background appended #${entry.num} ver=v${gameVer || "?"}`);
  console.log(`[fetch-bg] wrote ${MD_PATH}`);
  return true;
};

export { run };

const selfPath = fileURLToPath(import.meta.url);
const invokedDirectly = !!process.argv[1] && path.resolve(process.argv[1]).toLowerCase() === selfPath.toLowerCase();
if (invokedDirectly) {
  run()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error(`[fetch-bg] error: ${e.message}`);
      process.exit(1);
    });
}
