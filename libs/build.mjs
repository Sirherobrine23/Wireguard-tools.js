import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import child_process from "node:child_process";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const prebuilds = path.resolve(__dirname, "../prebuilds");
const build = path.resolve(__dirname, "../build/Release");
const nodeGyp = path.resolve(createRequire(import.meta.url).resolve("node-gyp"), "../../bin/node-gyp.js");
const env = Object.assign({}, process.env);

async function fork(...args) {
  return new Promise((resolve, reject) => {
    const child = child_process.fork(...args);
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`Process exited with code ${code} and signal ${signal}`));
    });
  });
};

async function exist(path) {
  return fs.open(path).then(() => true).catch(() => false);
}

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

if (process.argv.slice(2).at(0) === "build") {
  let archs = [];
  if (process.argv.includes("--auto")) {
    if (process.platform === "linux") archs.push("x64", "arm64");
    else archs.push(process.arch);
  } else {
    process.argv.slice(2).filter(f => f.startsWith("--arch=")).map(arch => arch.slice(7));
    if (archs.length <= 0) archs.push(process.arch);
  }
  for (const arch of Array.from(new Set(archs))) {
    console.log("Bulding to %O\n", arch);
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

    await fork(nodeGyp, ["rebuild", "-j", "max", "--arch="+arch], {stdio: "inherit", env});
    const files = (await fs.readdir(build)).filter(f => f.endsWith(".node"));
    if (await exist(path.join(prebuilds, `${process.platform}_${arch}`))) await fs.rm(path.join(prebuilds, `${process.platform}_${arch}`), {recursive: true, force: true});
    await fs.mkdir(path.join(prebuilds, `${process.platform}_${arch}`), {recursive: true});
    for (const file of files) await fs.rename(path.join(build, file), path.join(prebuilds, `${process.platform}_${arch}`, file));
  }
} else if (!(await exist(path.join(prebuilds, `${process.platform}_${process.arch}`)) || await exist(build))) {
  await fork(nodeGyp, ["rebuild", "-j", "max"], {stdio: "inherit", env});
}