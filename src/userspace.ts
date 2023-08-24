import { promises as fs } from "node:fs";
import net, { isIPv4 } from "node:net";
import path from "node:path";
import { createInterface as readline } from "node:readline";
import { finished } from "node:stream/promises";

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

export async function parseWgDevice(deviceName: string): Promise<wireguardInterface> {
  if (!deviceName || deviceName.length <= 2) throw new Error("Set valid device name");
  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const config: wireguardInterface = {} as any;

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
    else if (keyName === "endpoint") (config.peers ||= {})[latestPeer].endpoint = value;
    else if (keyName === "persistent_keepalive_interval") (config.peers ||= {})[latestPeer].keepInterval = Number(value);
    else if (keyName === "rx_bytes") (config.peers ||= {})[latestPeer].rxBytes = Number(value);
    else if (keyName === "tx_bytes") (config.peers ||= {})[latestPeer].txBytes = Number(value);
    else if (keyName === "last_handshake_time_sec") (config.peers ||= {})[latestPeer].lastHandshake = new Date(Number(value) * 1000);
    else if (keyName === "allowed_ip") {
      if (!value) return;
      (config.peers ||= {})[latestPeer].allowedIPs = ((config.peers ||= {})[latestPeer].allowedIPs||[]).concat(value);
    } else if (keyName === "preshared_key") {
      if (value === "0000000000000000000000000000000000000000000000000000000000000000") return;
      (config.peers ||= {})[latestPeer].presharedKey = Buffer.from(value, "hex").toString("base64");
    } else if (keyName === "public_key") {
      const keyDecode = Buffer.from(value, "hex").toString("base64");
      if (previewKey === "public_key") {
        config.publicKey = latestPeer;
        (config.peers ||= {})[keyDecode] = (config.peers ||= {})[latestPeer];
        delete (config.peers ||= {})[latestPeer];
        latestPeer = keyDecode;
      } else (config.peers ||= {})[(latestPeer = keyDecode)] = {};
    }
    previewKey = keyName;
  });

  await new Promise((done, reject) => tetrisBreak.on("error", reject).once("close", done));
  await finished(client.end());
  return Object.assign({peers: {}}, config);
}

export async function addDevice(deviceName: string, interfaceConfig: wireguardInterface) {
  if (!deviceName || deviceName.length <= 2) throw new Error("Set valid device name");

  const client = await connectSocket(path.join(defaultPath, deviceName).concat(".sock"));
  const writel = (...data: (string|number|boolean)[]) => client.write(("").concat(...(data.map(String)), "\n"));
  // Init set config in interface
  writel("set=1");

  // Keys
  if (typeof interfaceConfig.privateKey === "string" && interfaceConfig.privateKey.length > 0) writel(("private_key="), (Buffer.from(interfaceConfig.privateKey, "base64").toString("hex")));
  if (typeof interfaceConfig.publicKey === "string" && interfaceConfig.publicKey.length > 0) writel(("private_key="), (Buffer.from(interfaceConfig.publicKey, "base64").toString("hex")));

  // Port listening
  if (interfaceConfig.portListen !== undefined && Math.floor(interfaceConfig.portListen) >= 0) writel(("listen_port="), ((Math.floor(interfaceConfig.portListen))));

  // fwmark
  if (Math.floor(interfaceConfig.fwmark) >= 0) writel(("fwmark="), ((Math.floor(interfaceConfig.fwmark))));

  // Replace peer's
  if (interfaceConfig.replacePeers) writel("replace_peers=true");

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
    const err = new WgError("Invalid send config, check log");
    err.payload = payload;
    throw err;
  }
  return;
}