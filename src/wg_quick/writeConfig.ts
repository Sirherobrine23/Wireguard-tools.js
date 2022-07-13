import * as fs from "node:fs/promises";
import * as fsOld from "node:fs";
import * as path from "node:path";

export type ipObject = {
  ip: string,
  subnet: number
};

type base = {
  interface: {
    /** Private key */
    private: string
  },
  peer: {
    [publicKey: string]: {
      /** Config file comments */
      commend?: string,
      /** preshared key */
      preshared?: string,
      /** accept only certain ip, example: 8.8.8.8, 1.1.1.1 */
      allowIp: ipObject[]
    }
  }
};

export type clientConfig = base & {
  interface: {
    address: ipObject[],
    DNS?: string[]
  },
  peer: {
    [publicKey: string]: {
      Endpoint: {host: string, port: number},
      Keepalive?: number
    }
  }
};

export type serverConfig = base & {
  interface: {
    /** port to wireguard listen port, default `51820` */
    portListen: number,
    /** Wireguard interface IPs */
    ip: ipObject[],
    /**
     * iptables|ntables rule after creating the Wireguard interface.
     * @example ```json
     * {"up": ["iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT", "iptables -A FORWARD -i wg0 -j ACCEPT", "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", "ip6tables -A FORWARD -i wg0 -j ACCEPT", "ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"], "down": ["iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT", "iptables -D FORWARD -i wg0 -j ACCEPT", "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE", "ip6tables -D FORWARD -i wg0 -j ACCEPT", "ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"]}
     * ```
    */
    post?: {up?: string[], down?: string[]},
    /**
    * iptables|ntables rule before creating the Wireguard interface.
    * @example ```json
    * {"up": ["iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT", "iptables -A FORWARD -i wg0 -j ACCEPT", "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE", "ip6tables -A FORWARD -i wg0 -j ACCEPT", "ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"], "down": ["iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT", "iptables -D FORWARD -i wg0 -j ACCEPT", "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE", "ip6tables -D FORWARD -i wg0 -j ACCEPT", "ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"]}
    * ```
   */
    pre?: {up?: string[], down?: string[]},
  }
};

const isClient = (config: clientConfig | serverConfig): config is clientConfig => (config as clientConfig).interface.address !== undefined;
export default async function writeConfig(configbject: clientConfig, interfaceName: string): Promise<string>;
export default async function writeConfig(configbject: serverConfig, interfaceName: string): Promise<string>;
export default async function writeConfig(configbject: clientConfig|serverConfig, interfaceName: string): Promise<string> {
  if (!(fsOld.existsSync("/etc/wireguard"))) throw new Error("/etc/wireguard not found");
  let wireguardConfigString = "[Interface]\n";
  if (isClient(configbject)) {
    wireguardConfigString += `Address = ${configbject.interface.address.map(ip => `${ip.ip}/${ip.subnet}`).join(", ")}\n`;
    if (configbject.interface.DNS) wireguardConfigString += `DNS = ${configbject.interface.DNS.join(", ")}\n`;
  } else {
    wireguardConfigString += `ListenPort = ${configbject.interface.portListen}\n`;
    wireguardConfigString += `Address = ${configbject.interface.ip.map(ip => `${ip.ip}/${ip.subnet}`).join(", ")}\n`;
  }
  wireguardConfigString += `PrivateKey = ${configbject.interface.private}\n`;

  // Add Peers
  for (const peerPub of Object.keys(configbject.peer)) {
    wireguardConfigString += "\n";
    if (configbject.peer[peerPub].commend) wireguardConfigString += `### ${configbject.peer[peerPub].commend.replace(/\r?\n/g, "\n### ")}\n`;
    wireguardConfigString += `[Peer]\n`;
    wireguardConfigString += `PublicKey = ${peerPub}\n`;
    wireguardConfigString += `AllowedIPs = ${configbject.peer[peerPub].allowIp.map(ip => `${ip.ip}/${ip.subnet}`).join(", ")}\n`;
    if (configbject.peer[peerPub].preshared) wireguardConfigString += `PresharedKey = ${configbject.peer[peerPub].preshared}\n`;
    if (isClient(configbject)) {
      wireguardConfigString += `Endpoint = ${configbject.peer[peerPub].Endpoint.host}:${configbject.peer[peerPub].Endpoint.port}\n`;
      if (configbject.peer[peerPub].Keepalive) wireguardConfigString += `Keepalive = ${configbject.peer[peerPub].Keepalive}\n`;
    }
  }
  await fs.writeFile(path.join("/etc/wireguard", `${interfaceName}.conf`), wireguardConfigString);
  return wireguardConfigString;
}