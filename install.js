const childprocess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
if (!/node_modules/.test(process.env.PATH)) process.env.PATH += path.delimiter+path.join(process.cwd(), "node_modules/.bin");
if (fs.existsSync("./package.json")) {
  if (require("./package.json").name !== "wireguard-tools.js") {
    process.chdir("./node_modules/wireguard-tools.js");
    console.log("Wireguard-tools folder: %s", process.cwd());
  }
}

const outCpp = path.join(process.cwd(), "wireguard_bridge.node");
function clean(nodeCpp = true) {
  if (fs.existsSync(path.join(process.cwd(), "build"))) fs.rmSync(path.join(process.cwd(), "build"), { recursive: true });
  if (nodeCpp) {
    if (fs.existsSync(outCpp)) fs.rmSync(outCpp);
  }
}

function moveFile() {
  const ReleaseFile = path.join(process.cwd(), "build/Release/wireguard_bridge.node");
  const debugFile = path.join(process.cwd(), "build/Debug/wireguard_bridge.node");
  if (fs.existsSync(ReleaseFile)) return fs.renameSync(ReleaseFile, outCpp);
  else if (fs.existsSync(debugFile)) return fs.renameSync(debugFile, outCpp);
  else {
    console("Build error");
    process.exit(1);
  }
}

function build() {
  clean();
  const result = childprocess.spawnSync("node-gyp", [`--target=${process.version}`, `--real_openssl_major=${/^\d+/.exec(process.versions.openssl)[0]}`, "rebuild"], { stdio: !process.argv.some(arg => arg === "--silent") ? "inherit": "pipe" });
  if (result.error || result.status !== 0) {
    console.log("Failed to build binding");
    if (!!result.stdout) console.log(result.stdout.toString());
    if (!!result.stderr) console.log(result.stderr.toString());
    process.exit(1);
  }
  else moveFile();
}

if (process.argv.some(arg => arg === "--install")||!fs.existsSync(outCpp)) {
  clean();
  build();
  clean(false);
} else if (process.argv.some(arg => arg === "--clean")) clean();

process.exit(0);