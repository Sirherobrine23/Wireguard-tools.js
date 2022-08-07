const childprocess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const silentBuild = !!process.argv.some(arg => arg === "--silent");
const debugBuild = !!process.argv.some(arg => arg === "--debug");
const outNodeFile = path.join(process.cwd(), "wireguard_bridge.node");
const libnlSource = path.join(process.cwd(), "libnlSource");
if (!process.env.CFLAGS) process.env.CFLAGS = "";
if (!process.env.LDFLAGS) process.env.LDFLAGS = "";

function build() {
  const argsBuild = [`--target=${process.version}`, `--real_openssl_major=${/^\d+/.exec(process.versions.openssl)[0]}`];
  if (debugBuild) argsBuild.push("--debug");
  if (fs.existsSync(path.join(process.cwd(), "build"))) fs.rmSync(path.join(process.cwd(), "build"), { recursive: true });
  if (fs.existsSync(outNodeFile)) fs.rmSync(outNodeFile);

  childprocess.execFileSync("node-gyp", [...argsBuild, "rebuild"], { stdio: silentBuild ? "pipe" : "inherit" });
  const ReleaseFile = path.join(process.cwd(), "build/Release/wireguard_bridge.node");
  const debugFile = path.join(process.cwd(), "build/Debug/wireguard_bridge.node");
  if (fs.existsSync(ReleaseFile)) return fs.renameSync(ReleaseFile, outNodeFile);
  else if (fs.existsSync(debugFile)) return fs.renameSync(debugFile, outNodeFile);
}

if (process.argv.some(arg => arg === "--all")||process.argv.some(arg => arg === "--nodegyp")||!fs.existsSync(outNodeFile)) build();

process.exit(0);
