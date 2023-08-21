import { promises as fs } from "node:fs";
import net from "node:net";
import path from "node:path";
import { finished } from "node:stream/promises";
import { createInterface as readline } from "node:readline";

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
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean;
  peers: {
    [peerPublicKey: string]: peerConfig;
  }
};

export class WgError extends Error {
  payload?: string;
}

/** default location to run socket's */
export const defaultPath = (process.env.WIRWGUARD_GO_RUN||"").length > 0 ? path.resolve(process.cwd(), process.env.WIRWGUARD_GO_RUN) : process.platform === "win32" ? "\\\\.\\pipe\\WireGuard" : "/var/run/wireguard";

async function connectSocket(path: string): Promise<net.Socket> {
  return new Promise<net.Socket>((done, reject) => {
    const client = net.createConnection(path);
    return client.once("connect", () => done(client)).once("error", reject);
  });
}

export async function listDevices() {
  return (await fs.readdir(defaultPath).catch(() => [])).map(inter => {
    if (inter.endsWith(".sock")) inter = inter.slice(0, -5);
    return inter;
  });
}

export async function parseWgDevice(deviceName: string) {
  if (!deviceName || deviceName.length <= 2) throw new Error("Set valid device name");
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const config: wireguardInterface = { peers: {} };

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
    else if (keyName === "preshared_key") config.peers[latestPeer].presharedKey = Buffer.from(value, "hex").toString("base64");
    else if (keyName === "private_key") config.privateKey = Buffer.from(value, "hex").toString("base64");
    else if (keyName === "listen_port") config.portListen = Number(value);
    else if (keyName === "endpoint") config.peers[latestPeer].endpoint = value;
    else if (keyName === "persistent_keepalive_interval") config.peers[latestPeer].keepInterval = Number(value);
    else if (keyName === "rx_bytes") config.peers[latestPeer].rxBytes = Number(value);
    else if (keyName === "tx_bytes") config.peers[latestPeer].txBytes = Number(value);
    else if (keyName === "last_handshake_time_sec") config.peers[latestPeer].lastHandshake = new Date(Number(value) * 1000);
    else if (keyName === "allowed_ip") config.peers[latestPeer].allowedIPs.push(value);
    else if (keyName === "public_key") {
      const keyDecode = Buffer.from(value, "hex").toString("base64");
      if (previewKey === "public_key") {
        config.publicKey = latestPeer;
        config.peers[keyDecode] = config.peers[latestPeer];
        delete config.peers[latestPeer];
        latestPeer = keyDecode;
      } else config.peers[(latestPeer = keyDecode)] = { allowedIPs: [] };
    }
    previewKey = keyName;
  });

  await new Promise((done, reject) => tetrisBreak.on("error", reject).once("close", done));
  await finished(client.end());
  return config;
}

export async function addDevice(deviceName: string, interfaceConfig: wireguardInterface) {
  if (!deviceName || deviceName.length <= 2) throw new Error("Set valid device name");
  const socketLocation = path.join(defaultPath, deviceName).concat(".sock");
  const config = [ "set=1" ]; // Init set config in interface

  // Keys
  if (typeof interfaceConfig.privateKey === "string" && interfaceConfig.privateKey.length > 0) config.push(("private_key=").concat(Buffer.from(interfaceConfig.privateKey, "base64").toString("hex")));
  if (typeof interfaceConfig.publicKey === "string" && interfaceConfig.publicKey.length > 0) config.push(("private_key=").concat(Buffer.from(interfaceConfig.publicKey, "base64").toString("hex")));

  // Port listening
  if (interfaceConfig.portListen !== undefined && Math.floor(interfaceConfig.portListen) >= 0) config.push(("listen_port=").concat(String(Math.floor(interfaceConfig.portListen))));

  // fwmark
  if (Math.floor(interfaceConfig.fwmark) >= 0) config.push(("fwmark=").concat(String(Math.floor(interfaceConfig.fwmark))));

  // Replace peer's
  if (interfaceConfig.replacePeers) config.push("replace_peers=true");

  // Mount peer
  for (const publicKey of Object.keys(interfaceConfig.peers||{})) {
    const { presharedKey, endpoint, keepInterval, removeMe, allowedIPs = [] } = interfaceConfig.peers[publicKey];

    config.push(("public_key=").concat(Buffer.from(publicKey, "base64").toString("hex"))); // Public key
    if (removeMe) {
      config.push("remove=true"); // Remove peer
      continue;
    }

    if (typeof endpoint === "string" && endpoint.length > 0) config.push(("endpoint=").concat(endpoint));
    if (typeof presharedKey === "string" && presharedKey.length > 3) config.push(("preshared_key=").concat(Buffer.from(presharedKey, "base64").toString("hex")));
    if (typeof keepInterval === "number" && Math.floor(keepInterval) > 0) config.push(("persistent_keepalive_interval=").concat(String(Math.floor(keepInterval))));
    if (allowedIPs.length > 0) {
      config.push("replace_allowed_ips=true");
      for (const IIP of allowedIPs) config.push(("allowed_ip=").concat(IIP));
    }
  }

  const client = await connectSocket(socketLocation);
  client.write(config.join("\n").concat("\n\n"));
  let payloadBody: Buffer[] = [];
  client.on("data", function processBuff (buff) {
    payloadBody.push(buff);
    if (buff.at(-1) === 0x0A && buff.at(-2) === 0x0A) {
      client.removeListener("data", processBuff); // Remove data callback
      client.end(); // Close conenction
    }
  });
  await finished(client, { error: true });
  const payload = Buffer.concat(payloadBody).toString("utf8");
  const payloadKeys = payload.split("\n").filter(i => i.length > 3).map(line => { const iit = line.indexOf("="); return [ line.slice(0, iit), line.slice(iit+1) ]; })
  if (payloadKeys.at(-1)[1] !== "0") {
    const err = new WgError("Invalid send config, check log");
    err.payload = payload;
    throw err;
  }
  return;
}