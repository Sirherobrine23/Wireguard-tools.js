import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import childPromise from "../lib/childPromise";

/*
peer: ***=
  preshared key: (hidden)
  endpoint: 1.1.1.1:49238
  allowed ips: 10.153.19.249/32, 2002:a99:13f9::/128
  latest handshake: 2 hours, 9 minutes, 5 seconds ago
  transfer: 9.25 KiB received, 23.34 KiB sent
*/
export type peerInfo = {
  key: {preshared?: string, public: string},
  allowd_ips: string[],
  endpoint?: string,
  latest_handshake?: Date,
  transfer?: {recived: number, send: number}
}

async function extractPeersInfo(wgInterface: string): Promise<peerInfo[]> {
  if (wgInterface === "all") throw new Error("Not work for all");
  const exec = await childPromise("wg", ["show", wgInterface, "dump"], {});
  const peers: peerInfo[] = [];
  const peersMatch = [...exec.stdout.matchAll(/(.*=)\s+(.*=)\s+((\(none\)|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+))\s+([0-9./,:a-zA-Z]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+.*/g)];
  peersMatch.forEach(peer => {
    if (!peer) return;
    const [pub, preshared, endpoint_1, endpoint_2, allowed_ips, rx, tx] = peer.slice(1);
    const data: peerInfo = {
      allowd_ips: allowed_ips.split(",").map(x => x.trim()),
      key: {
        public: pub,
        preshared: preshared||undefined
      },
    };
    if (!!(endpoint_2||endpoint_1) && (endpoint_2||endpoint_1) !== "(none)") data.endpoint = endpoint_2||endpoint_1;
    if ((!!tx && !isNaN(parseInt(tx))) && !!rx && !isNaN(parseInt(rx))) data.transfer = {recived: parseInt(rx), send: parseInt(tx)};
    peers.push(data);
  });
  return peers;
}

export type wgInterface = {
  name: string,
  rx: number,
  tx: number,
  peers: peerInfo[]
};

async function getInterfaces(): Promise<wgInterface[]> {
  const interfaces = Object.keys(os.networkInterfaces());
  const devices = await Promise.all(interfaces.map(async (wgInterface): Promise<wgInterface|void> => {
    const classPath = path.join("/sys/class/net", wgInterface);
    try {
      if (!fs.existsSync(classPath)) return;
      if (!/DEVTYPE=wireguard/.test(await fs.promises.readFile(path.join(classPath, "uevent"), "utf8"))) return;
      return {
        name: wgInterface,
        rx: parseInt(await fs.promises.readFile(path.join(classPath, "statistics/rx_bytes"), "utf8")),
        tx: parseInt(await fs.promises.readFile(path.join(classPath, "statistics/tx_bytes"), "utf8")),
        peers: await extractPeersInfo(wgInterface)
      }
    } catch (_) {}
    return;
  }));
  return devices.filter(x => !!x) as wgInterface[];
}

export default function Status(wgIface: string): Promise<wgInterface>;
export default function Status(wgIface?: string): Promise<wgInterface[]>;
export default async function Status(wgIface?: string): Promise<wgInterface[]|wgInterface>  {
  console.info("this api is under development, and for now it remains dependent on wg commands and wg-quick");
  const wgInterfaces = await getInterfaces();
  if (typeof wgIface === "string") {
    let __wgInterface = wgInterfaces.find(x => x.name === wgIface);
    if (!__wgInterface) throw new Error("Interface not exists");
    return __wgInterface;
  }
  return wgInterfaces;
}