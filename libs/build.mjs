// @ts-check
import child_process from "node:child_process";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url)); // Fix ESM __dirname
const nodeGyp = path.resolve(createRequire(import.meta.url).resolve("node-gyp"), "../../bin/node-gyp.js"); // Node gyp script
const env = Object.assign({}, process.env);

const prebuilds = path.resolve(__dirname, "../prebuilds");
const buildDir = path.resolve(__dirname, "../build") /* Build Directory */, buildRelease = path.join(buildDir, "Release"), buildDebug = path.join(buildDir, "Debug");
async function exist(path) {
  return fs.open(path).then(e => e.close().then(() => true, () => true), () => false);
}

/**
 *
 * @param {string} command
 * @param {string[]} args
 * @param {Omit<import("child_process").ForkOptions, "stdio">} options
 */
async function fork(command, args, options) {
  if (options) options["stdio"] = undefined;
  console.log("%s", command, ...args);
  return new Promise((done, reject) => {
    const child = child_process.fork(command, args, options);
    child.on("error", reject);
    if (child.stdout) child.stdout.once("data", function log(data) { process.stdout.write(data); if (child.stdout) child.stdout.once("data", log); });
    if (child.stderr) child.stderr.once("data", function log(data) { process.stderr.write(data); if (child.stderr) child.stderr.once("data", log); });
    child.once("exit", (code, sig) => {
      if (code === 0) return done(0);
      return reject(new Error(("Process exit with ").concat(String(code), " and signal ", String(sig))));
    });
  });
}

// Fix CI prebuild download
if (await exist(prebuilds)) {
  for (const folderLayer1 of await fs.readdir(prebuilds)) {
    let toRm = false;
    for (const folderLayer2 of await fs.readdir(path.join(prebuilds, folderLayer1))) {
      const currentFolder = path.join(prebuilds, folderLayer1, folderLayer2);
      if ((await fs.lstat(currentFolder)).isDirectory()) {
        toRm = true;
        const newFolder = path.join(prebuilds, folderLayer2);
        console.log("\nMigrate from %O to %O", currentFolder, newFolder);
        if (await exist(newFolder)) await fs.rm(newFolder, { recursive: true, force: true });
        await fs.mkdir(newFolder, { recursive: true });
        await Promise.all((await fs.readdir(currentFolder)).map(async p => {
          console.log("Copy %O", path.join(currentFolder, p));
          return fs.copyFile(path.join(currentFolder, p), path.join(newFolder, p))
        }));
        await fs.rm(currentFolder, { recursive: true, force: true });
      }
    }
    if (toRm) await fs.rm(path.join(prebuilds, folderLayer1), { recursive: true, force: true });
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
    else if (process.platform === "win32") archs.push("x64", "arm64");
    else if (process.platform === "darwin") archs.push("x64", "arm64");
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
    } else if (process.platform === "win32" && arch !== process.arch) {
      let skip = true;
      for (const vsPath of [ "C:\\Program Files (x86)\\Microsoft Visual Studio", "C:\\Program Files\\Microsoft Visual Studio" ]) {
        if (!(await exist(vsPath))) continue;
        const year = ((await fs.readdir(vsPath)).filter(s => !(isNaN(Number(s)))).sort((a, b) => (Number(a) < Number(b)) ? -1 : 0).at(-1));
        if (!year) continue;
        for (const vsEdition of await fs.readdir(path.join(vsPath, year))) {
          if (await exist(path.join(vsPath, year, vsEdition, "MSBuild\\Current\\Bin", arch))) {
            if (skip) skip = false;
            break;
          }
        }
        if (!skip) break;
      }
      if (skip) {
        console.info("Arch not avaible to copiler!");
        continue;
      }
    }

    try {
      console.log("Bulding to %O\n", arch);
      await fork(nodeGyp, ["rebuild", ...(process.platform !== "android"?["-j", "max"]:[]), ("--arch=").concat(arch)], {env});
      console.log("Migrating addons!");
      await migrateBuildAddon(process.platform, arch);
    } catch (err) {
      if (process.platform === "win32" && arch !== process.arch) continue;
      throw err;
    }
  }
} else if (!(await exist(path.join(prebuilds, `${process.platform}_${process.arch}`)) || await exist(buildRelease))) {
  await fork(nodeGyp, ["rebuild", ...(process.platform !== "android"?["-j", "max"]:[])], {env});
  await migrateBuildAddon(process.platform, process.arch);
}