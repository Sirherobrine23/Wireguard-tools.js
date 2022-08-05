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
const silentBuild = !!process.argv.some(arg => arg === "--silent");
const debugBuild = !!process.argv.some(arg => arg === "--debug");
const outNodeFile = path.join(process.cwd(), "wireguard_bridge.node");
const libnlSource = path.join(process.cwd(), "libnlSource");
if (!process.env.CFLAGS) process.env.CFLAGS = "";
if (!process.env.LDFLAGS) process.env.LDFLAGS = "";

function buildLibnl() {
  let CFLAGS = process.env.CFLAGS||"", LDFLAGS = process.env.LDFLAGS||"";
  const configureArgs = ["--prefix="+path.join(process.cwd(), "libnl"), "--disable-shared", "--disable-dynamic-linking"];
  if (!fs.existsSync(libnlSource)) childprocess.execFileSync("git", ["clone", "--depth=1", "https://github.com/thom311/libnl", libnlSource], {stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8"});

  if (process.platform === "android") {
    configureArgs.push("--disable-pthreads", "--disable-cli");
    CFLAGS = "-Dsockaddr_storage=__kernel_sockaddr_storage";
    LDFLAGS = "";
    try {
      childprocess.execFileSync("git", ["apply", path.join(process.cwd(), "patchs/android_libnl.patch")], {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8"});
    } catch (_err) {}
  } else {
    CFLAGS = (`${CFLAGS} -static -s`).trim();
    LDFLAGS = (`${LDFLAGS} -static`).trim();
  }
  CFLAGS = (`${CFLAGS} -fPIC`).trim(); LDFLAGS = (`${LDFLAGS} -fPIC`).trim();

  console.log("Building libnl");
  console.log("Auto generating configure script");
  childprocess.execFileSync("./autogen.sh", {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8", env: {
    ...process.env,
    CFLAGS,
    LDFLAGS,
  }});

  console.log("\nRunning configure");
  childprocess.execFileSync("./configure", configureArgs, {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8", env: {
    ...process.env,
    CFLAGS,
    LDFLAGS,
  }});

  console.log("\nRunning make");
  childprocess.execFileSync("make", {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8", env: {
    ...process.env,
    CFLAGS,
    LDFLAGS,
  }});

  console.log("\nInstalling libnl");
  if (fs.existsSync(path.join(process.cwd(), "libnl"))) fs.rmSync(path.join(process.cwd(), "libnl"), { recursive: true });
  childprocess.execFileSync("make", ["install"], {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8", env: {
    ...process.env,
    CFLAGS,
    LDFLAGS,
  }});

  console.log("\nCleaning up");
  childprocess.execFileSync("make", ["clean"], {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8"});
  childprocess.execSync("git restore . && rm -rf $(git status -s | awk '{print $2}')", {cwd: libnlSource, stdio: silentBuild ? "pipe" : "inherit", encoding: "utf8"});
  for (const FileFolder of fs.readdirSync(path.join(process.cwd(), "libnl"))) {
    if (FileFolder === "include"||FileFolder === "lib") continue;
    console.log("Removing %s", FileFolder);
    fs.rmSync(path.join(process.cwd(), "libnl", FileFolder), {recursive: true, force: true});
  }
  fs.rmSync(libnlSource, {recursive: true, force: true});
}

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

if (process.argv.some(arg => arg === "--all")||process.argv.some(arg => arg === "--libnl")) buildLibnl();
if (process.argv.some(arg => arg === "--all")||process.argv.some(arg => arg === "--nodegyp")||!fs.existsSync(outNodeFile)) build();

process.exit(0);
