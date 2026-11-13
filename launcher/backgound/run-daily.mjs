#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "./fetch-bg.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MD = path.join(__dirname, "backgound.md");

/** 向上查找git仓库根目录 */
function findGitRoot(dir) {
  let cur = dir;
  for (;;) {
    if (fs.existsSync(path.join(cur, ".git"))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

/** 只提交backgound.md 可选推送远程 */
function commitMd(gitRoot, mdRel) {
  execFileSync("git", ["add", mdRel], { cwd: gitRoot });
  const msg = `chore(launcher): update launcher background record (${new Date().toISOString().slice(0, 10)})`;
  execFileSync("git", ["commit", "-m", msg], { cwd: gitRoot });
  console.log(`[run-daily] committed ${mdRel}`);
  if (process.env.GIT_PUSH === "1" || process.env.GIT_PUSH === "true") {
    execFileSync("git", ["push"], { cwd: gitRoot });
    console.log("[run-daily] pushed to remote");
  }
}

console.log("[run-daily] fetching and recording background image...");

let changed = false;
try {
  changed = await run();
} catch (e) {
  console.error(`[run-daily] error: ${e.message}`);
  process.exit(1);
}

if (process.env.GITHUB_ACTIONS) {
  console.log(`[run-daily] CI mode, change=${changed}, commit/push handled by workflow`);
  process.exit(0);
}

const gitRoot = findGitRoot(__dirname);
if (!gitRoot) {
  console.log("[run-daily] not a git repo, updated local md only, skip commit");
  process.exit(0);
}

if (!changed) {
  console.log("[run-daily] md unchanged, skip commit");
  process.exit(0);
}

const mdRel = path.relative(gitRoot, MD).replace(/\\/g, "/");
commitMd(gitRoot, mdRel);
