#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BASE_URL,
  BASE_CONFIG,
  GAME_CONFIG,
  GAME_ID,
  LAUNCHER_VERSION,
  SALT,
  REGION,
  WORK_DIR,
  MD_PATH,
  IMAGE_DIR
} from "./config.js";

const DEFAULT_INTRO = `# StellaSora_CN 启动器背景图记录

> 自动抓取自 \`${BASE_URL}${BASE_CONFIG}\` 的 \`launcher_background_img\` 字段。`;

// 构造启动器接口签名鉴权头
const getAuthHeader = () => {
  const head = { game_tag: GAME_ID, time: Math.floor(Date.now() / 1000), version: LAUNCHER_VERSION };
  const sign = crypto.createHash("md5").update(JSON.stringify(head) + SALT).digest("hex");
  return JSON.stringify({ head, sign });
};

// 获取背景图链接与crc64
const fetchBackground = async () => {
  const res = await fetch(BASE_URL + BASE_CONFIG, {
    method: "GET",
    headers: { "Content-Type": "application/json;charset=UTF-8", Authorization: getAuthHeader() }
  });
  const json = await res.json();
  if (json.code !== 200) throw new Error(`base config error code=${json.code}`);
  const d = json.data || {};
  return { url: d.launcher_background_img || "", crc64: String(d.launcher_background_img_crc64 ?? "") };
};

// 从游戏配置接口取最新游戏版本 仅作兜底
const fetchGameVersion = async () => {
  try {
    const res = await fetch(BASE_URL + GAME_CONFIG, {
      method: "GET",
      headers: { "Content-Type": "application/json;charset=UTF-8", Authorization: getAuthHeader() }
    });
    const json = await res.json();
    if (json.code !== 200) return "";
    return String(json.data?.game_latest_version ?? "");
  } catch {
    return "";
  }
};

// 从ss_win.mani读取游戏版本
const readGameVersionFromMani = (filePath) => {
  try {
    const text = fs.readFileSync(filePath, "utf8");
    const m = text.match(/^\$GAME_VER:\s*(.+?)\s*$/m);
    return m ? m[1] : "";
  } catch {
    return "";
  }
};

// 解析游戏版本 优先环境变量 其次mani文件 兜底接口
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

// 下载背景图到工作目录
const downloadImage = async (url, dest) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download image error status=${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, buf);
  return buf.length;
};

// 解析已有markdown的简介与历史记录
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

// 按项目格式渲染markdown
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

// 写状态文件供上层workflow读取版本与产物路径
const saveState = (state) => {
  fs.mkdirSync(WORK_DIR, { recursive: true });
  fs.writeFileSync(path.join(WORK_DIR, "state.json"), JSON.stringify(state, null, 2), "utf8");
};

// 拉取背景 下载图片 更新md并返回状态
const run = async () => {
  const bg = await fetchBackground();
  if (!bg.url || !bg.crc64) throw new Error("no background image link fetched");
  const gameVer = await resolveGameVersion();
  if (!gameVer) throw new Error("no game version resolved");

  const tag = `v${gameVer}`;
  const imageName = `${tag}.jpg`;
  const imagePath = path.join(IMAGE_DIR, imageName);
  const size = await downloadImage(bg.url, imagePath);

  const today = new Date().toISOString().slice(0, 10);
  let intro = DEFAULT_INTRO;
  let entries = [];
  if (fs.existsSync(MD_PATH)) {
    const parsed = parseMd(fs.readFileSync(MD_PATH, "utf8"));
    intro = parsed.intro || DEFAULT_INTRO;
    entries = parsed.entries;
  }

  console.log(`[fetch-bg] region=${REGION} crc64=${bg.crc64}`);
  console.log(`[fetch-bg] game version=${tag}`);
  console.log(`[fetch-bg] downloaded ${imageName} ${(size / 1024).toFixed(1)}KB -> ${imagePath}`);

  const known = entries.find((e) => e.crc64 === bg.crc64);
  let appended = false;
  if (!known) {
    const maxNum = entries.reduce((mx, e) => Math.max(mx, e.num), -1);
    entries.push({ num: maxNum + 1, ver: tag, date: today, crc64: bg.crc64, link: bg.url });
    appended = true;
  }
  fs.writeFileSync(MD_PATH, buildMarkdown(intro, bg.url, entries));

  const state = {
    region: REGION,
    version: gameVer,
    tag,
    crc64: bg.crc64,
    url: bg.url,
    image: imageName,
    imagePath,
    mdPath: MD_PATH,
    appended
  };
  saveState(state);
  console.log(`[fetch-bg] wrote ${MD_PATH}`);
  console.log(`[fetch-bg] state -> ${path.join(WORK_DIR, "state.json")}`);
  return state;
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
