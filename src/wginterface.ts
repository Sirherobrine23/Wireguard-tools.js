import { promises as fs } from "node:fs";
import net from "node:net";
import { createInterface as readline } from "node:readline";
import { finished } from "node:stream/promises";
import path from "path";
import { promisify } from "util";
import { createConfig } from "./utils/config";
import * as ipManipulation from "./utils/ipm";
import * as keygen from "./utils/keygen";
import { randomInt } from "node:crypto";
const wg_binding = require("../libs/prebuildifyLoad.cjs")("wginterface", path.join(__dirname, ".."));

/** default location to run socket's */
export const defaultPath = (process.env.WIRWGUARD_GO_RUN||"").length > 0 ? path.resolve(process.cwd(), process.env.WIRWGUARD_GO_RUN) : process.platform === "win32" ? "\\\\.\\pipe\\WireGuard" : "/var/run/wireguard";
export const constants: { MAX_NAME_LENGTH: number } = wg_binding.constants;

export type peerConfig = {
  /** Mark this peer to be removed, any changes remove this option */
  removeMe?: boolean,
  presharedKey?: string,
  keepInterval?: number,
  /** Remote address or hostname to Wireguard connect */
  endpoint?: string,
  /** Accept connection from this address */
  allowedIPs?: string[],
  rxBytes?: number,
  txBytes?: number,
  lastHandshake?: Date,
};

export type wireguardInterface = {
  publicKey?: string;
  privateKey?: string;
  portListen?: number;
  fwmark?: number;
  Address?: string[];
  DNS?: string[];
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean;
  peers: {
    [peerPublicKey: string]: peerConfig;
  }
};

export class wgConfig extends Map<string, peerConfig> {
  publicKey?: string;
  privateKey?: string;
  portListen?: number;
  fwmark?: number;
  Address?: string[] = [];
  DNS?: string[] = [];
  replacePeers = true;

  constructor(config?: wireguardInterface) {
    super();
    if (!config) return;
    const { privateKey, publicKey, portListen, replacePeers, fwmark, Address, DNS, peers } = config;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.portListen = portListen;
    this.replacePeers = !!replacePeers;
    this.fwmark = fwmark;
    this.Address = Address || [];
    this.DNS = DNS || [];

    if (typeof peers === "object") {
      Object.keys(peers).forEach(pub => this.set(pub, peers[pub]));
    }
  }

  async newPeer(withPreshared?: boolean) {
    let peerKey: keygen.keyObjectPreshered;
    while (!peerKey) {
      peerKey = await keygen.keygenAsync(true);
      if (this.has(peerKey.public)) peerKey = undefined;
    }

    const allowedIPs = Array.from(this.values()).map(s => s.allowedIPs).flat(2).filter(s => net.isIPv4(s.split("/")[0]));
    const IPv4 = ipManipulation.randomIp(this.Address.at(this.Address.length === 1 ? 0 : randomInt(0, this.Address.length - 1)), allowedIPs), IPv6 = ipManipulation.toV6(IPv4);
    this.set(peerKey.public, {
      allowedIPs: [IPv4, IPv6],
      presharedKey: withPreshared ? peerKey.preshared : undefined
    });
    return Object.assign({}, { publicKey: peerKey.public }, this.get(peerKey.public));
  }

  toJSON(): wireguardInterface {
    const { privateKey, publicKey, portListen, replacePeers, fwmark, Address, DNS } = this;
    return {
      privateKey,
      publicKey,
      portListen,
      fwmark,
      replacePeers,
      Address,
      DNS,
      peers: Array.from(this).reduce((acc, [pubKey, info]) => Object.assign(acc, { [pubKey]: info}), {})
    };
  }

  toString() {
    return createConfig(this.toJSON());
  }
}

async function connectSocket(path: string): Promise<net.Socket> {
  return new Promise<net.Socket>((done, reject) => {
    const client = net.createConnection(path);
    return client.once("connect", () => done(client)).once("error", reject);
  });
}

/**
 * List all Wireguard interfaces
 * @returns Interfaces array
 */
export async function listDevices() {
  let interfaceNames: {from: "userspace"|"kernel", name: string}[] = [];
  if (typeof wg_binding.listDevicesAsync === "function") interfaceNames = interfaceNames.concat((await promisify(wg_binding.listDevicesAsync)() as string[]).map(name => ({from: "kernel", name})) );
  return interfaceNames.concat((await fs.readdir(defaultPath).catch((): string[] => [])).map(name => ({from: "userspace", name: name.endsWith(".sock") ? name.slice(0, -5) : name})));
}

/**
 * Get interface config.
 * @param deviceName - Wireguard interface name.
 * @returns
 */
export async function getConfig(deviceName: string): Promise<wireguardInterface> {
  const info = (await listDevices()).find(int => int.name === deviceName);
  if (!info) throw new Error("Create interface, not exists");
  if (info.from === "kernel") {
    if (typeof wg_binding.getConfigAsync === "function") return promisify(wg_binding.getConfigAsync)(deviceName);
    else throw new Error("Cannot get config");
  }
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const config = new wgConfig();

  let latestPeer: string, previewKey: string;
  client.write("get=1\n\n");
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

  await new Promise((done, reject) => tetrisBreak.on("error", reject).once("close", done));
  await finished(client.end());
  return config.toJSON();
}

/**
 * Delete wg interface if possible
 * @param deviceName - Wireguard interface name.
 * @returns
 */
export async function deleteInterface(deviceName: string): Promise<void> {
  if (typeof wg_binding.deleteInterfaceAsync === "function") return promisify(wg_binding.deleteInterfaceAsync)(deviceName);
  return fs.rm(path.join(defaultPath, deviceName).concat(".sock"), { force: true });
}

/**
 * Set Wireguard interface config.
 * @param deviceName - Wireguard interface name.
 * @param interfaceConfig - Peers and Interface config.
 */
export async function setConfig(deviceName: string, interfaceConfig: wireguardInterface): Promise<void> {
  if (typeof wg_binding.setConfigAsync === "function") return promisify(wg_binding.setConfigAsync)(deviceName, interfaceConfig);
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const writel = (...data: (string|number|boolean)[]) => client.write(("").concat(...(data.map(String)), "\n"));
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
  if (typeof interfaceConfig.publicKey === "string" && interfaceConfig.publicKey.length > 0) writel(("private_key="), (Buffer.from(interfaceConfig.publicKey, "base64").toString("hex")));

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