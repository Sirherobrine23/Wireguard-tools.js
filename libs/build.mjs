// @ts-check
import child_process from "node:child_process";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
const __dirname = path.dirname(fileURLToPath(import.meta.url)); // Fix ESM __dirname
const nodeGyp = path.resolve(createRequire(import.meta.url).resolve("node-gyp"), "../../bin/node-gyp.js"); // Node gyp script
const env = Object.assign({}, process.env);

const prebuilds = path.resolve(__dirname, "../prebuilds");
const buildDir = path.resolve(__dirname, "../build") /* Build Directory */, buildRelease = path.join(buildDir, "Release"), buildDebug = path.join(buildDir, "Debug");
async function exist(path) {
  return fs.open(path).then(() => true, () => false);
}

/**
 *
 * @param {string} command
 * @param {string[]} args
 * @param {Omit<import("child_process").ForkOptions, "stdio">} options
 */
async function fork(command, args, options) {
  if (options) options["stdio"] = undefined;
  return new Promise((done, reject) => {
    const child = child_process.fork(command, args, options);
    child.on("error", reject);
    if (child.stdout) child.stdout.pipe(process.stdout);
    if (child.stderr) child.stderr.pipe(process.stderr);
    child.once("exit", (code, sig) => {
      if (code === 0) return done(0);
      return reject(new Error(("Process exit with ").concat(String(code), " and signal ", String(sig))));
    });
  });
}

// Fix CI prebuild download
if (await exist(prebuilds)) {
  const prebuildsFolder = (await fs.readdir(prebuilds)).filter(file => file.startsWith("prebuilds_"));
  for (const folder of prebuildsFolder) {
    for (const ff of await fs.readdir(path.join(prebuilds, folder))) {
      const folderNewPath = path.resolve(prebuilds, folder, "..", ff);
      if (await exist(folderNewPath)) await fs.rm(folderNewPath, {recursive: true, force: true});
      await fs.mkdir(folderNewPath);
      for (const file of await fs.readdir(path.join(prebuilds, folder, ff))) {
        await fs.rename(path.join(prebuilds, folder, ff, file), path.join(folderNewPath, file));
      }
    }
    await fs.rm(path.join(prebuilds, folder), {recursive: true, force: true});
  }
}

/**
 *
 * @param {string} platform
 * @param {string} arch
 */
async function migrateBuildAddon(platform, arch) {
  const files = (await fs.readdir(buildRelease)).filter(f => f.endsWith(".node"));
  const targetPath = path.join(prebuilds, `${platform}_${arch}`);
  if (await exist(targetPath)) await fs.rm(targetPath, {recursive: true, force: true});
  await fs.mkdir(targetPath, {recursive: true});
  for (const file of files) {
    console.log("Move %O to %O", path.join(buildRelease, file), path.join(targetPath, file));
    await fs.rename(path.join(buildRelease, file), path.join(targetPath, file));
  }
  await fs.rm(buildDir, { recursive: true, force: true });
}

if (process.argv.slice(2).at(0) === "build") {
  let archs = [];
  if (process.argv.includes("--clean")) {
    if (await exist(buildDir)) await fs.rm(buildDir, { recursive: true, force: true });
    if (await exist(prebuilds)) await fs.rm(prebuilds, { recursive: true, force: true });
  }
  if (process.argv.includes("--auto")) {
    if (process.platform === "linux") archs.push("x64", "arm64");
    else archs.push(process.arch);
  } else {
    process.argv.slice(2).filter(f => f.startsWith("--arch=")).map(arch => arch.slice(7));
    if (archs.length <= 0) archs.push(process.arch);
  }
  for (const arch of Array.from(new Set(archs))) {
    if (process.platform === "linux" && arch !== process.arch) {
      if (arch === "x64") {
        // x86_64-linux-gnu-gcc
        env.CC = "x86_64-linux-gnu-gcc";
        env.CXX = "x86_64-linux-gnu-g++";
      } else if (arch === "arm64") {
        // aarch64-linux-gnu-gcc
        env.CC = "aarch64-linux-gnu-gcc";
        env.CXX = "aarch64-linux-gnu-g++";
      }
    }

    console.log("Bulding to %O\n", arch);
    await fork(nodeGyp, ["rebuild", "-j", "max", ("--arch=").concat(arch)], {env});
    console.log("Migrating addons!");
    await migrateBuildAddon(process.platform, arch);
  }
} else if (!(await exist(path.join(prebuilds, `${process.platform}_${process.arch}`)) || await exist(buildRelease))) {
  await fork(nodeGyp, ["rebuild", "-j", "max"], {env});
  await migrateBuildAddon(process.platform, process.arch);
}