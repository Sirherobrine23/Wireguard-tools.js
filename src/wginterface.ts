import { promises as fs } from "fs";
import { isIPv4, createConnection as netConnection } from "net";
import path from "path";
import readline from "readline";
import { finished } from "stream/promises";
if (process.platform === "win32") global.WIREGUARD_DLL_PATH = path.join(__dirname, "../addons/tools/win/wireguard-nt/bin", process.arch === "x64" ? "amd64" : process.arch, "wireguard.dll");
const addon = require("../libs/prebuildifyLoad.cjs")("wginterface");

export const { constants } = addon as { constants: { WG_B64_LENGTH: number, WG_LENGTH: number, MAX_NAME_LENGTH: number, driveVersion: string } };

/** default location to run socket's */
const defaultPath = (process.env.WIRWGUARD_GO_RUN||"").length > 0 ? path.resolve(process.cwd(), process.env.WIRWGUARD_GO_RUN) : process.platform === "win32" ? "\\\\.\\pipe\\WireGuard" : "/var/run/wireguard";

async function exists(path: string) {
  return fs.open(path).then(o => o && (o.close().then(() => true, () => true))||true, () => false);
}

export interface Peer {
  /** Preshared key to peer */
  presharedKey?: string;

  /** keepInterval specifies the persistent keepalive interval for this peer */
  keepInterval?: number;

  /** Remote address or hostname to Wireguard connect or endpoint is the most recent source address used for communication by peer. */
  endpoint?: string;

  /** AllowedIPs specifies a list of allowed IP addresses in CIDR notation (`0.0.0.0/0`, `::/0`) */
  allowedIPs?: string[];
};

export interface PeerSet extends Peer {
  /** Mark this peer to be removed, any changes remove this option */
  removeMe?: boolean;
}

export interface PeerGet extends Peer {
  /** ReceiveBytes indicates the number of bytes received from this peer. */
  rxBytes?: number;

  /** TransmitBytes indicates the number of bytes transmitted to this peer. */
  txBytes?: number;

  /** Last peer Handshake */
  lastHandshake?: Date;
}

export interface WgConfigBase<T extends Peer> {
  /** privateKey specifies a private key configuration */
  privateKey?: string;
  /** publicKey specifies a public key configuration */
  publicKey?: string;
  /** ListenPort specifies a device's listening port, 0 is random */
  portListen?: number;
  /** FirewallMark specifies a device's firewall mark */
  fwmark?: number;
  /** Interface IP address'es */
  Address?: string[];

  /** Interface peers */
  peers: Record<string, T>;
}

export interface WgConfigGet extends WgConfigBase<PeerGet> {}
export interface WgConfigSet extends WgConfigBase<PeerSet> {
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean;
}

/**
 * Get Wireguard devices and locations
 */
export async function listDevices() {
  let devices: {from: "userspace"|"kernel", name: string, path?: string}[] = [];
  if (typeof addon.listDevices === "function") devices = devices.concat(await addon.listDevices());
  if (await exists(defaultPath)) (await fs.readdir(defaultPath)).forEach(file => devices.push({ from: "userspace", name: file.endsWith(".sock") ? file.slice(0, -5) : file, path: path.join("/var/run/wireguard", file) }));
  return devices;
}

/**
 * Delete wireguard interface if present
 * @param wgName - Interface name
 * @returns
 */
export async function deleteInterface(wgName: string): Promise<void> {
  if (typeof addon.deleteInterface === "function") return addon.deleteInterface(wgName);
  const dev = (await listDevices()).find(s => s.name === wgName);
  if (dev && dev.path) return fs.rm(dev.path, { force: true });
}

/**
 * Set Wireguard config in interface
 *
 * in the Linux and Windows create if not exist interface
 *
 * @param wgName - Interface name
 * @param config - Interface config
 */
export async function setConfig(wgName: string, config: WgConfigSet): Promise<void> {
  if (process.platform === "darwin") {
    if (!(wgName.match(/^tun([0-9]+)$/))) throw new Error("Invalid name, example to valid: tun0");
    // Replace to tun name
    // const devNames = Object.keys(networkInterfaces()).filter(s => s.toLowerCase().startsWith("tun"));
    // for (let i = 0n; i < BigInt(Number.MAX_SAFE_INTEGER); i++) if (devNames.indexOf((wgName = ("tun").concat(i.toString())))) break;
  }

  if (typeof addon.setConfig === "function") return addon.setConfig(wgName, config);
  const client = netConnection(path.join(defaultPath, (wgName).concat(".sock")));
  const writel = (...data: any[]) => client.write(data.map(String).join("").concat("\n"));
  // Init set config in interface
  writel("set=1");

  // Port listening
  if (config.portListen !== undefined && Math.floor(config.portListen) >= 0) writel(("listen_port="), ((Math.floor(config.portListen))));

  // fwmark
  if (Math.floor(config.fwmark) >= 0) writel(("fwmark="), ((Math.floor(config.fwmark))));

  // Replace peer's
  if (config.replacePeers) writel("replace_peers=true");

  // Keys
  if (typeof config.privateKey === "string" && config.privateKey.length > 0) writel(("private_key="), (Buffer.from(config.privateKey, "base64").toString("hex")));

  // Mount peer
  for (const publicKey of Object.keys(config.peers||{})) {
    const { presharedKey, endpoint, keepInterval, removeMe, allowedIPs = [] } = config.peers[publicKey];

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
      const fixed = allowedIPs.map(i => i.indexOf("/") === -1 ? i.concat("/", (isIPv4(i) ? "32" : "128")) : i)
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
}

/**
 * Get wireguard interface config
 * @param wgName - Interface name
 * @returns
 */
export async function getConfig(wgName: string): Promise<WgConfigGet> {
  if (typeof addon.getConfig === "function") return addon.getConfig(wgName);
  const info = (await listDevices()).find(int => int.name === wgName);
  if (!info) throw new Error("Create interface, not exists");
  const client = netConnection(path.join(defaultPath, wgName.concat(".sock")));
  const config: WgConfigGet = Object();
  let latestPeer: string, previewKey: string;

  const tetrisBreak = readline.createInterface(client);
  tetrisBreak.on("line", function lineProcess(line) {
    if (line === "") tetrisBreak.removeListener("line", lineProcess).close();
    const findout = line.indexOf("="), keyName = line.slice(0, findout), value = line.slice(findout+1);
    if (findout <= 0) return;
    if (keyName === "errno" && value !== "0") throw new Error(("wireguard-go error, code: ").concat(value));

    // Drop
    if ((["last_handshake_time_nsec", "protocol_version", "errno"]).includes(keyName)) return;
    else if (keyName === "private_key") config.privateKey = Buffer.from(value, "hex").toString("base64");
    else if (keyName === "listen_port") config.portListen = Number(value);
    else if (keyName === "endpoint") ((config.peers||(config.peers = {}))[latestPeer]).endpoint = value;
    else if (keyName === "persistent_keepalive_interval") ((config.peers||(config.peers = {}))[latestPeer]).keepInterval = Number(value);
    else if (keyName === "rx_bytes") ((config.peers||(config.peers = {}))[latestPeer]).rxBytes = Number(value);
    else if (keyName === "tx_bytes") ((config.peers||(config.peers = {}))[latestPeer]).txBytes = Number(value);
    else if (keyName === "last_handshake_time_sec") ((config.peers||(config.peers = {}))[latestPeer]).lastHandshake = new Date(Number(value) * 1000);
    else if (keyName === "allowed_ip") {
      if (!value) return;
      ((config.peers||(config.peers = {}))[latestPeer]).allowedIPs = (((config.peers||(config.peers = {}))[latestPeer]).allowedIPs||[]).concat(value);
    } else if (keyName === "preshared_key") {
      if (value === "0000000000000000000000000000000000000000000000000000000000000000") return;
      ((config.peers||(config.peers = {}))[latestPeer]).presharedKey = Buffer.from(value, "hex").toString("base64");
    } else if (keyName === "public_key") {
      const keyDecode = Buffer.from(value, "hex").toString("base64");
      if (previewKey !== "public_key") (config.peers||(config.peers = {}))[latestPeer] = {};
      else {
        config.publicKey = latestPeer;
        (config.peers||(config.peers = {}))[keyDecode] = (config.peers||(config.peers = {}))[latestPeer];
        delete (config.peers||(config.peers = {}))[latestPeer];
        latestPeer = keyDecode;
      }
    }
    previewKey = keyName;
  });
  client.write("get=1\n\n");
  await new Promise((done, reject) => tetrisBreak.on("error", reject).once("close", done));
  await finished(client.end());
  return config;
}