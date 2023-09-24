const { promises: fs } = require("node:fs");
const { createInterface: readline } = require("node:readline");
const { finished } = require("node:stream/promises");
const { promisify } = require("util");
const net = require("node:net");
const path = require("path");

if (process.platform === "win32") global.WIREGUARD_DLL_PATH = path.join(__dirname, "../addons/tools/win/wireguard-nt/bin", process.arch === "x64" ? "amd64" : process.arch, "wireguard.dll");
const wg_binding = require("../libs/prebuildifyLoad.cjs")("wginterface", path.join(__dirname, ".."));

/** default location to run socket's */
const defaultPath = (process.env.WIRWGUARD_GO_RUN||"").length > 0 ? path.resolve(process.cwd(), process.env.WIRWGUARD_GO_RUN) : process.platform === "win32" ? "\\\\.\\pipe\\WireGuard" : "/var/run/wireguard";
const constants = wg_binding.constants;
module.exports = { defaultPath, constants, listDevices, setConfig, getConfig, deleteInterface };

/**
 *
 * @param {string} path
 * @returns {Promise<net.Socket>}
 */
async function connectSocket(path) {
  return new Promise((done, reject) => {
    const client = net.createConnection(path);
    return client.once("connect", () => done(client)).once("error", reject);
  });
}

/**
 * List all Wireguard interfaces
 * @returns {Promise<{from: "userspace"|"kernel", name: string}[]>} Interfaces array
 */
async function listDevices() {
  let interfaceNames = [];
  if (typeof wg_binding.listDevicesAsync === "function") interfaceNames = interfaceNames.concat(await wg_binding.listDevicesAsync());
  return interfaceNames.concat((await fs.readdir(defaultPath).catch(() => [])).map(name => ({from: "userspace", name: name.endsWith(".sock") ? name.slice(0, -5) : name})));
}

/**
 * Get interface config.
 * @param {string} deviceName - Wireguard interface name.
 * @returns
 */
async function getConfig(deviceName) {
  const info = (await listDevices()).find(int => int.name === deviceName);
  if (!info) throw new Error("Create interface, not exists");
  if (info.from === "kernel") {
    if (typeof wg_binding.getConfigAsync === "function") return wg_binding.getConfigAsync(deviceName);
    else throw new Error("Cannot get config");
  }
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const config = new (require("./utils/config")).wgConfig();

  /** @type {string} */
  let latestPeer,
  /** @type {string} */
  previewKey;
  const tetrisBreak = readline(client);
  tetrisBreak.on("line", function lineProcess(line) {
    if (line === "") tetrisBreak.removeListener("line", lineProcess).close();
    const findout = line.indexOf("="), keyName = line.slice(0, findout), value = line.slice(findout+1);
    if (findout <= 0) return;
    if (keyName === "errno" && value !== "0") throw new Error(("wireguard-go error, code: ").concat(value));

    // Drop
    if ((["last_handshake_time_nsec", "protocol_version", "errno"]).includes(keyName)) return;
    else if (keyName === "private_key") config.privateKey = Buffer.from(value, "hex").toString("base64");
    else if (keyName === "listen_port") config.portListen = Number(value);
    else if (keyName === "endpoint") config.get(latestPeer).endpoint = value;
    else if (keyName === "persistent_keepalive_interval") config.get(latestPeer).keepInterval = Number(value);
    else if (keyName === "rx_bytes") config.get(latestPeer).rxBytes = Number(value);
    else if (keyName === "tx_bytes") config.get(latestPeer).txBytes = Number(value);
    else if (keyName === "last_handshake_time_sec") config.get(latestPeer).lastHandshake = new Date(Number(value) * 1000);
    else if (keyName === "allowed_ip") {
      if (!value) return;
      config.get(latestPeer).allowedIPs = (config.get(latestPeer).allowedIPs||[]).concat(value);
    } else if (keyName === "preshared_key") {
      if (value === "0000000000000000000000000000000000000000000000000000000000000000") return;
      config.get(latestPeer).presharedKey = Buffer.from(value, "hex").toString("base64");
    } else if (keyName === "public_key") {
      const keyDecode = Buffer.from(value, "hex").toString("base64");
      if (previewKey !== "public_key") config.set((latestPeer = keyDecode), {});
      else {
        config.publicKey = latestPeer;
        config.set(keyDecode, config.get(latestPeer));
        config.delete(latestPeer);
        latestPeer = keyDecode;
      }
    }
    previewKey = keyName;
  });
  client.write("get=1\n\n");
  await new Promise((done, reject) => tetrisBreak.on("error", reject).once("close", done));
  await finished(client.end());
  return config.toJSON();
}

/**
 * Delete wg interface if possible
 * @param {string} deviceName - Wireguard interface name.
 * @returns
 */
async function deleteInterface(deviceName) {
  const info = (await listDevices()).find(int => int.name === deviceName);
  if (!info) throw new Error("Interface not exists");
  if (info.from === "userspace") return fs.rm(path.join(defaultPath, deviceName).concat(".sock"), { force: true });
  if (typeof wg_binding.deleteInterfaceAsync !== "function") throw new Error("Cannot delete interface from kernel!");
  return promisify(wg_binding.deleteInterfaceAsync)(deviceName);
}

/**
 * Set Wireguard interface config.
 * @param {string} deviceName - Wireguard interface name.
 * @param interfaceConfig - Peers and Interface config.
 */
async function setConfig(deviceName, interfaceConfig) {
  if (typeof wg_binding.setConfigAsync === "function") return wg_binding.setConfigAsync(deviceName, interfaceConfig);
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const writel = (...data) => client.write(("").concat(...(data.map(String)), "\n"));
  // Init set config in interface
  writel("set=1");

  // Port listening
  if (interfaceConfig.portListen !== undefined && Math.floor(interfaceConfig.portListen) >= 0) writel(("listen_port="), ((Math.floor(interfaceConfig.portListen))));

  // fwmark
  if (Math.floor(interfaceConfig.fwmark) >= 0) writel(("fwmark="), ((Math.floor(interfaceConfig.fwmark))));

  // Replace peer's
  if (interfaceConfig.replacePeers) writel("replace_peers=true");

  // Keys
  if (typeof interfaceConfig.privateKey === "string" && interfaceConfig.privateKey.length > 0) writel(("private_key="), (Buffer.from(interfaceConfig.privateKey, "base64").toString("hex")));

  // Mount peer
  for (const publicKey of Object.keys(interfaceConfig.peers||{})) {
    const { presharedKey, endpoint, keepInterval, removeMe, allowedIPs = [] } = interfaceConfig.peers[publicKey];

    // Public key
    writel(("public_key="), (Buffer.from(publicKey, "base64").toString("hex")));
    if (removeMe) {
      writel("remove=true"); // Remove peer
      continue;
    }

    if (typeof endpoint === "string" && endpoint.length > 0) writel(("endpoint="), (endpoint));
    if (typeof presharedKey === "string" && presharedKey.length > 3) writel(("preshared_key="), (Buffer.from(presharedKey, "base64").toString("hex")));
    if (typeof keepInterval === "number" && Math.floor(keepInterval) > 0) writel(("persistent_keepalive_interval="), (String(Math.floor(keepInterval))));
    if (allowedIPs.length > 0) {
      writel("replace_allowed_ips=true");
      const fixed = allowedIPs.map(i => i.indexOf("/") === -1 ? i.concat("/", (net.isIPv4(i) ? "32" : "128")) : i)
      for (const IIP of fixed) writel(("allowed_ip="), (IIP));
    }
  }

  let payload = "";
  client.once("data", function processBuff(buff) {
    payload = payload.concat(buff.toString("utf8"));
    if (payload[payload.length - 1] === "\n" && payload[payload.length - 2] === "\n") {
      client.end(); // Close conenction
      return;
    }
    client.once("data", processBuff);
  });
  client.write("\n");
  await finished(client, { error: true });
  const payloadKeys = payload.split("\n").filter(i => i.length > 3).map(line => { const iit = line.indexOf("="); return [ line.slice(0, iit), line.slice(iit+1) ]; })
  if (payloadKeys.at(-1)[1] !== "0") {
    const err = new Error("Invalid send config, check log");
    throw err;
  }
  return;
}