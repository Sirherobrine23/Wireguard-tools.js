import * as fs from "node:fs/promises";
import * as fsOld from "node:fs";
import * as path from "node:path";
import type { wireguardInterface } from "../wg_binding";

export type ipObject = {ip: string, subnet: number};
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
    /** Interface IPs */
    address: ipObject[],
    /** Interface Domain name resolve, example: `["8.8.8.8", "1.1.1.1"]` */
    DNS?: string[]
  },
  peer: {
    [publicKey: string]: {
      /** Target host and port to peer connect */
      Endpoint: {host: string, port: number},
      /** Time to send a packet to maintain connection */
      Keepalive?: number,
      /** Time to send a packet to maintain connection */
      PersistentKeepalive?: number,
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

/** Return Client config string */
export function writeConfig(configbject: clientConfig): string;
/** Return server config string */
export function writeConfig(configbject: serverConfig): string;
/** Create config string */
export function writeConfig(configbject: clientConfig|serverConfig): string {
  let wireguardConfigString = "[Interface]\n";
  const isClient = (config: clientConfig | serverConfig): config is clientConfig => (config as clientConfig).interface.address !== undefined;
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
      if (configbject.peer[peerPub].PersistentKeepalive && !configbject.peer[peerPub].Keepalive) wireguardConfigString += `PersistentKeepalive = ${configbject.peer[peerPub].PersistentKeepalive}\n`;
      if (configbject.peer[peerPub].Keepalive && configbject.peer[peerPub].PersistentKeepalive) wireguardConfigString += `Keepalive = ${configbject.peer[peerPub].Keepalive}\n`;
    }
  }
  return wireguardConfigString;
}

// Line matchs
const configRegex = /^(\[(Interface|Peer)\])|((PresharedKey|PublicKey|PrivateKey|AllowedIPs|Endpoint|PersistentKeepalive|Keepalive|DNS|ListenPort|Address|PreDown|PostDown|PreUp|PostUp)\s?\=\s?(.*))/;

function filterStringConfig(config: string): string {
  return config.split(/\r?\n/).filter(line => {
    // if (!lineMath.test(line)) console.log("Result: %o, Line: '%s'", lineMath.test(line), line);
    return configRegex.test(line);
  }).map(line => line.trim()).join("\n");
}

function parseKeys(env: string): {[key: string]: string} {
  const keys: {[key: string]: string} = {};
  for (const line of env.split(/\r?\n/)) {
    const data = line.match(configRegex)||[];
    const [,,,, key, value] = data;
    if (!!key && !!value) {
      if (!keys[key?.trim()]) keys[key?.trim()] = value.trim();
      else keys[key?.trim()] = `${keys[key?.trim()]}, ${value.trim()}`;
    }
  }
  return keys;
}

export function parseClientConfig(config: string): clientConfig {
  const returnConfig = parseConfig(config);
  if (returnConfig.type === "client") return returnConfig.data as clientConfig;
  throw new Error("Config is not client config");
}
export function parseServerConfig(config: string): serverConfig {
  const returnConfig = parseConfig(config);
  if (returnConfig.type === "server") return returnConfig.data as serverConfig;
  throw new Error("Config is not server config");
}

export function parseConfig(configString: string): {type: "client"|"server", data: clientConfig|serverConfig} {
  if (!configString) throw new Error("Config is empty");
  if (!configString.trim()) throw new Error("Config is empty");
  // Remove comments
  configString = filterStringConfig(configString);
  let arrayIndex = -1;
  const objectValue = [];
  for (let line of configString.split(/\r?\n/)) {
    if (/\[Interface|Peer\]/.test(line)) {
      arrayIndex++
      objectValue[arrayIndex] = [];
      line = line.replace(/\[(Interface|Peer)\]/, (_, a1) => a1);
    };
    if (arrayIndex === -1) continue;
    objectValue[arrayIndex].push(line);
  }
  const typesConfig = objectValue.map(Object => {const type = Object.shift(); const doc = parseKeys(Object.join("\n")); return {type, doc}});
  if (typesConfig.filter(type => type.type === "Interface").length > 1 && 0 < typesConfig.filter(type => type.type === "Interface").length) throw new Error("Invalid config");
  const interfaceConfig = typesConfig.filter(type => type.type === "Interface")[0].doc;
  const peerConfig = typesConfig.filter(type => type.type === "Peer").map(type => type.doc);
  if (!!interfaceConfig.Address && !!interfaceConfig.ListenPort) {
    // Init JSON config
    const serverConfig: serverConfig = {
      interface: {
        private: interfaceConfig.PrivateKey,
        portListen: parseInt(interfaceConfig.ListenPort),
        ip: [],
      },
      peer: {}
    };

    // Parse IPs
    if (!/,/.test(interfaceConfig.Address)) serverConfig.interface.ip.push({ip: interfaceConfig.Address.split("/")[0], subnet: parseInt(interfaceConfig.Address.split("/")[1])});
    else {
      for (const ip of interfaceConfig.Address.split(/,/)) {
        if (!ip.trim()) continue;
        serverConfig.interface.ip.push({
          ip: ip.split(/\//)[0].trim(),
          subnet: parseInt(ip.split(/\//)[1].trim())
        });
      }
    }

    // Parse Peers
    for (const peer of peerConfig) {
      if (!peer.PublicKey) throw new Error("PublicKey not found to peer");
      if (!peer.AllowedIPs) throw new Error("AllowedIPs required to peer");
      if (serverConfig.peer[peer.PublicKey]) {
        console.warn("Peer with PublicKey %s already exists", peer.PublicKey);
        continue;
      }
      serverConfig.peer[peer.PublicKey] = {
        allowIp: peer.AllowedIPs.split(/,/).filter(ip => !!ip.trim()).map(ip => ({ip: ip.split("/")[0], subnet: parseInt(ip.split("/")[1])})),
      };
      if (!!peer.PresharedKey?.trim()) serverConfig.peer[peer.PublicKey].preshared = peer.PresharedKey.trim();
    };
    return {type: "server", data: serverConfig};
  } else if (!!interfaceConfig.Address && !!interfaceConfig.Address) {
    const clientConfig: clientConfig = {
      interface: {
        private: interfaceConfig.PrivateKey,
        address: interfaceConfig.Address.split(/,/).filter(ip => !!ip.trim()).map(ip => ({ip: ip.split("/")[0], subnet: parseInt(ip.split("/")[1])})),
      },
      peer: {}
    };
    // DNS
    if (!!interfaceConfig.DNS) clientConfig.interface.DNS = interfaceConfig.DNS.split(/,/).filter(ip => !!ip.trim());

    // Peers
    for (const peer of peerConfig) {
      if (!peer.PublicKey) throw new Error("PublicKey not found to peer");
      if (!peer.Endpoint) throw new Error("Endpoint required to peer");
      if (clientConfig.peer[peer.PublicKey]) {
        console.warn("Peer with PublicKey %s already exists", peer.PublicKey);
        continue;
      }
      const url = new URL(`udp://${peer.Endpoint}`);
      clientConfig.peer[peer.PublicKey] = {
        allowIp: peer.AllowedIPs.split(/,/).filter(ip => !!ip.trim()).map(ip => ({ip: ip.split("/")[0], subnet: parseInt(ip.split("/")[1])})),
        Endpoint: {
          host: url.hostname,
          port: parseInt(url.port)
        }
      };
      if (!!peer.PresharedKey?.trim()) clientConfig.peer[peer.PublicKey].preshared = peer.PresharedKey.trim();
    }
    return {type: "client", data: clientConfig};
  }
  throw new Error("Config is invalid");
}

/**
 * Parse wireguard config file and return client or server config object.
 *
 * Config files are stored in /etc/wireguard/<interfaceName>.conf
 */
export async function readConfig(interfaceName: string) {
  if (!interfaceName) throw new Error("Interface name is required");
  if (!(fsOld.existsSync("/etc/wireguard"))) throw new Error("/etc/wireguard not found");
  if (interfaceName.includes(".conf")) interfaceName = interfaceName.replace(".conf", "");
  if (!(fsOld.existsSync(path.join("/etc/wireguard", `${interfaceName}.conf`)))) throw new Error(`${interfaceName}.conf not found`);
  return parseConfig(await fs.readFile(path.join("/etc/wireguard", `${interfaceName}.conf`), "utf8"));
}

const ipRaw = (ip: string): {ip: string, subnet: number} => {
  const [ipAddress, subnet] = ip.split("/");
  return {
    ip: ipAddress?.trim(),
    subnet: !!subnet?.trim() ? parseInt(subnet) : /\:\:/.test(ipAddress?.trim()) ? 128 : 32
  }
};

/**
 *
 */
export function prettyConfig(wgConfig: wireguardInterface): clientConfig|serverConfig {
  if (!!wgConfig.Address && !!wgConfig.portListen) {
    const serverConfig: serverConfig = {
      interface: {
        private: wgConfig.privateKey,
        portListen: wgConfig.portListen,
        ip: []
      },
      peer: {}
    };
    if (wgConfig?.Address?.length > 0 || wgConfig.Address) serverConfig.interface.ip.push(...wgConfig.Address.map(ipRaw));
    for (const peerPublicKey in wgConfig.peers) {
      serverConfig.peer[peerPublicKey] = {
        preshared: wgConfig.peers[peerPublicKey].presharedKey,
        allowIp: [],
      };
      if(wgConfig.peers[peerPublicKey].allowedIPs) serverConfig.peer[peerPublicKey].allowIp = wgConfig.peers[peerPublicKey].allowedIPs.map(ipRaw)
    }
    return serverConfig;
  }
  const clientConfig: clientConfig = {
    interface: {
      private: wgConfig.privateKey,
      address: [],
    },
    peer: {}
  };
  if (wgConfig?.Address?.length > 0 || wgConfig.Address) clientConfig.interface.address.push(...wgConfig.Address.map(ipRaw));
  for (const peerPublicKey in wgConfig.peers) {
    clientConfig.peer[peerPublicKey] = {
      preshared: wgConfig.peers[peerPublicKey].presharedKey,
      Keepalive: wgConfig.peers[peerPublicKey].keepInterval,
      Endpoint: {host: "", port: 0},
      allowIp: []
    };
    if (wgConfig.peers[peerPublicKey].allowedIPs) clientConfig.peer[peerPublicKey].allowIp.push(...wgConfig.peers[peerPublicKey].allowedIPs.map(ipRaw));
    if (!/::/.test(wgConfig.peers[peerPublicKey].endpoint)) {
      clientConfig.peer[peerPublicKey].Endpoint.host = wgConfig.peers[peerPublicKey].endpoint?.split(":")[0];
      clientConfig.peer[peerPublicKey].Endpoint.port = parseInt(wgConfig.peers[peerPublicKey].endpoint?.split(":")[1]);
    } else {
      const [host, port] = wgConfig.peers[peerPublicKey].endpoint?.match(/^\[(.*)\]:(\d+)$/)!;
      clientConfig.peer[peerPublicKey].Endpoint.host = host;
      clientConfig.peer[peerPublicKey].Endpoint.port = parseInt(port);
    }
  }
  return clientConfig;
}