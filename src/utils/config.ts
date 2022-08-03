import * as fs from "node:fs/promises";
import * as fsOld from "node:fs";
import * as path from "node:path";

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


export function filterStringConfig(config: string): string {
  const lineMath = /^(\[(Interface|Peer)\])|((PresharedKey|PublicKey|PrivateKey|AllowedIPs|Endpoint|Keepalive|DNS|ListenPort|Address|PreDown|PostDown|PreUp|PostUp)\s?\=\s?.*)/;
  return config.split(/\r?\n/).filter(line => {
    // if (!lineMath.test(line)) console.log("Result: %o, Line: '%s'", lineMath.test(line), line);
    return lineMath.test(line);
  }).join("\n");
}

export function parseKeys(env: string): {[key: string]: string} {
  const keys: {[key: string]: string} = {};
  for (const line of env.split(/\r?\n/)) {
    const [key, value] = (line.match(/(PresharedKey|PublicKey|PrivateKey|AllowedIPs|Endpoint|Keepalive|DNS|ListenPort|Address|PreDown|PostDown|PreUp|PostUp)\s?\=\s?(.*)/)||[]).slice(1);
    if (!!key) keys[key.trim()] = value.trim();
  }
  return keys;
}

/** Return Client config string */
export function writeConfig(configbject: clientConfig): string;
/** Return server config string */
export function writeConfig(configbject: serverConfig): string;
/** Write config file */
export function writeConfig(configbject: clientConfig, interfaceName: string): Promise<void>;
/** Write server config file */
export function writeConfig(configbject: serverConfig, interfaceName: string): Promise<void>;
/** Create config string, if interfaceName is not specified return config string */
export function writeConfig(configbject: clientConfig|serverConfig, interfaceName?: string): Promise<void>|string {
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
      if (configbject.peer[peerPub].Keepalive) wireguardConfigString += `Keepalive = ${configbject.peer[peerPub].Keepalive}\n`;
    }
  }
  if (!interfaceName) return wireguardConfigString;
  else {
    if (!(fsOld.existsSync("/etc/wireguard"))) throw new Error("/etc/wireguard not found");
    return fs.writeFile(path.join("/etc/wireguard", `${interfaceName}.conf`), wireguardConfigString);
  }
}

// export function parseConfig(configString: string): {type: "client", data: clientConfig};
// export function parseConfig(configString: string): {type: "server", data: serverConfig};
export function parseConfig(configString: string): {type: "client"|"server", data: clientConfig | serverConfig} {
  if (!configString) throw new Error("Config is empty");
  // Remove comments
  configString = configString.replace(/###[^\n]*\n/g, "");
  const Get = configString.split(/\n?\[([A-Za-z]+)\]/g).map(x => x.trim()).filter(x => !!x);
  const def: Array<{Key: string, data: string}> = [];
  while (Get.length > 0) {
    let data = {Key: Get.shift(), data: Get.shift()};
    if(data.Key === "Peer"||data.Key === "Interface") {
      configString = configString.replace(data.Key, "").replace("[]", "").replace(data.data, "").trim();
      def.push(data);
    }
  }
  if (!!configString) throw new Error("Invalid wireguard config");
  if (def.filter(x => x.Key === "Interface").length > 2 && def.filter(x => x.Key === "Interface").length < 0) throw new Error("Invalid wireguard config");
  // Check if it is a client
  const parseSet = (lines: string[]) => {
    const toRe: {key: string, value: string}[] = [];
    for (const line of lines) {
      const set = line.match(/([A-Za-z0-9]+)\s+?\=\s+?(.*)/);
      if (!!set)  {
        const [key, value] = set.slice(1);
        toRe.push({key: key.trim(), value: value.trim()});
      } else console.log("Invalid line:", line);
    }
    return toRe;
  }
  const InterfaceData = parseSet(def.filter(x => x.Key === "Interface")[0].data.trim().split(/\n/g).map(x => x.trim()));
  if (!!InterfaceData.find(({key}) => key === "Address") && !!InterfaceData.find(({key}) => key === "ListenPort")) {
    const config: serverConfig = {
      interface: {
        private: InterfaceData.find(({key}) => key === "PrivateKey")!.value,
        portListen: parseInt(InterfaceData.find(({key}) => key === "ListenPort")!.value),
        ip: InterfaceData.find(({key}) => key === "Address")!.value.split(/,/g).map(x => ({ip: x.split("/")[0].trim(), subnet: parseInt(x.split("/")[1].trim())})),
      },
      peer: {},
    };
    if (InterfaceData.find(({key}) => key === "PostUp")!.value||InterfaceData.find(({key}) => key === "PostDown")!.value) {
      config.interface.post = {};
      if (InterfaceData.find(({key}) => key === "PostUp")!.value) config.interface.post.up = InterfaceData.find(({key}) => key === "PostUp")!.value.split(/;|&&/).map(x => x.trim());
      if (InterfaceData.find(({key}) => key === "PostDown")!.value) config.interface.post.down = InterfaceData.find(({key}) => key === "PostDown")!.value.split(/;|&&/).map(x => x.trim());
    }
    if (InterfaceData.find(({key}) => key === "PreUp")!.value||InterfaceData.find(({key}) => key === "PreDown")!.value) {
      config.interface.pre = {};
      if (InterfaceData.find(({key}) => key === "PreUp")!.value) config.interface.pre.up = InterfaceData.find(({key}) => key === "PreUp")!.value.split(/;|&&/).map(x => x.trim());
      if (InterfaceData.find(({key}) => key === "PreDown")!.value) config.interface.pre.down = InterfaceData.find(({key}) => key === "PreDown")!.value.split(/;|&&/).map(x => x.trim());
    }
    for (const peer of def.filter(x => x.Key === "Peer")) {
      const findValue = (key: string): string => peerData.find(({key: k}) => k === key)?.value;
      const peerData = parseSet(peer.data.trim().split(/\n/g).map(x => x.trim()).filter(x => !!x));;
      const PublicKey = findValue("PublicKey")!;
      if (!!config.peer[PublicKey]) throw new Error("Duplicate public key");
      config.peer[PublicKey] = {
        preshared: findValue("PresharedKey"),
        allowIp: (!!findValue("AllowedIPs"))?findValue("AllowedIPs")!.split(",").map(x => ({ip: x.split("/")[0].trim(), subnet: parseInt(x.split("/")[1].trim())})):[],
      };
    }
    return {type: "server", data: config};
  }
  const config: clientConfig = {
    interface: {
      address: InterfaceData.find(({key}) => key === "Address")!.value.split(",").map(x => ({ip: x.split("/")[0].trim(), subnet: parseInt(x.split("/")[1].trim())})),
      DNS: InterfaceData.find(({key}) => key === "DNS")?.value.split(",").map(x => x.trim()),
      private: InterfaceData.find(({key}) => key === "PrivateKey")!.value,
    },
    peer: {},
  };
  for (const peer of def.filter(x => x.Key === "Peer")) {
    const peerData = parseSet(peer.data.trim().split(/\n/g).map(x => x.trim()).filter(x => !!x));
    const findValue = (key: string): string => peerData.find(({key: k}) => k === key)?.value;
    const PublicKey = findValue("PublicKey")!;
    if (!!config.peer[PublicKey]) throw new Error("Duplicate public key");
    config.peer[PublicKey] = {
      Endpoint: {host: findValue("Endpoint")?.split(":")[0].trim(), port: parseInt(findValue("Endpoint")!.split(":")[1].trim())},
      preshared: findValue("PresharedKey"),
      commend: findValue("Comment"),
      allowIp: (!!findValue("AllowedIPs"))?findValue("AllowedIPs").split(",").map(x => ({ip: x.split("/")[0].trim(), subnet: parseInt(x.split("/")[1].trim())})):[],
    };
    if (findValue("Keepalive")) config.peer[PublicKey].Keepalive = parseInt(findValue("Keepalive"));
    if (peerData.filter(x => /^(AllowedIPs|Endpoint|PresharedKey|Comment|Keepalive)$/.test(x.key)).length > 1) console.log("Warning: multiple invalid keys in peer %s", PublicKey);
  }
  return {type: "client", data: config};
}

/**
 * Parse wireguard config file and return client or server config object.
 *
 * Config files are stored in /etc/wireguard/<interfaceName>.conf
 */
export async function readConfig(interfaceName: string): Promise<{type: "client"|"server", data: clientConfig | serverConfig}> {
  if (!(fsOld.existsSync("/etc/wireguard"))) throw new Error("/etc/wireguard not found");
  if (!(fsOld.existsSync(path.join("/etc/wireguard", `${interfaceName}.conf`)))) throw new Error(`${interfaceName}.conf not found`);
  return parseConfig(await fs.readFile(path.join("/etc/wireguard", `${interfaceName}.conf`), "utf8"));
}