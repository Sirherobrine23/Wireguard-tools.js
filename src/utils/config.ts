import { wireguardInterface } from "../wginterface";

/**
 * Create wg-quick config file
 * @param param0 - Config object input
 * @returns Config file string
 */
export function createConfig({ portListen, publicKey, privateKey, Address, DNS, peers = {} }: wireguardInterface) {
  const configString: string[] = ["[Interface]"];
  if (typeof publicKey === "string" && publicKey.length > 0) configString.push(("PublicKey = ").concat(publicKey));
  if (typeof privateKey === "string" && privateKey.length > 0) configString.push(("PrivateKey = ").concat(privateKey));
  if (portListen >= 1 && portListen <= ((2 ** 16) - 1)) configString.push(("ListenPort = ").concat(String(portListen)));
  if (Array.isArray(Address) && Address.length > 0) configString.push(("Address = ").concat(...(Address.join(", "))));
  if (Array.isArray(DNS) && DNS.length > 0) configString.push(("DNS = ").concat(DNS.join(", ")));

  // Peers mount
  for (const pubKey of Object.keys(peers)) {
    configString.push("", "[Peer]", ("PublicKey = ").concat(pubKey));
    const { presharedKey, allowedIPs, keepInterval, endpoint } = peers[pubKey];
    if (typeof presharedKey === "string" && presharedKey.length > 0) configString.push(("PresharedKey = ").concat(presharedKey));
    if (typeof endpoint === "string" && endpoint.length > 0) configString.push(("Endpoint = ").concat(endpoint));
    if (typeof keepInterval === "number" && keepInterval > 0) configString.push(("PersistentKeepalive = ").concat(String(keepInterval)));
    if (Array.isArray(allowedIPs) && allowedIPs.length > 0) configString.push(("AllowedIPs = ").concat(allowedIPs.join(", ")));
  }

  return configString.join("\n").trim();
}

/**
 * Parse wg-quick config and return config object
 * @param wgConfig - Config file
 * @returns Config object
 */
export function parseConfig(wgConfig: string|Buffer): wireguardInterface {
  if (Buffer.isBuffer(wgConfig)) wgConfig = wgConfig.toString();
  const lines = wgConfig.trim().split(/\r?\n/).map(s => s.trim()).filter(s => (!!s) && !(s.startsWith("#")));
  return Object.assign({}, {peers: {}}, lines.reduce<{ start: number, end?: number }[]>((acc, line, index) => {
    if (line.toLowerCase() === "[peer]") {
      if (typeof acc.at(-1).start === "undefined") acc.at(-1).start = index;
      else {
        acc.at(-1).end = index - 1;
        acc.push({ start: index });
      }
    }
    return acc;
  }, [{start: 0}]).map(({ start, end }) => {
    const [ target, ...linesConfig ] = lines.slice(start, end);
    return {
      target: target.toLowerCase() === "[peer]" ? "peer" : "interface",
      linesConfig: linesConfig.map(s => {
        const ii = s.indexOf("="), keyName = s.substring(0, ii).trim(), value = s.substring(ii+1).trim();
        return { keyName, value };
      })
    };
  }).reduce<wireguardInterface>((acc, info) => {
    if (info.target === "interface") {
      for (const { keyName, value } of info.linesConfig) {
        if (keyName.toLowerCase() === "privatekey") acc.privateKey = value;
        else if (keyName.toLowerCase() === "publickey") acc.publicKey = value;
        else if (keyName.toLowerCase() === "address") acc.Address = ([acc.Address, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
        else if (keyName.toLowerCase() === "dns") acc.DNS = ([acc.DNS, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
        else if (keyName.toLowerCase() === "listenport") {
          const port = parseInt(value);
          if (port >= 1 && port <= ((2 ** 16) - 1)) acc.portListen = port;
        }
      }
    } else if (info.target === "peer") {
      acc.peers = (acc.peers || {});
      const publicKey = info.linesConfig.find(s => s.keyName.toLowerCase() === "publickey")?.value;
      if (!!publicKey) {
        for (const { keyName, value } of info.linesConfig) {
          if (keyName.toLowerCase() === "publickey") continue;
          else if (keyName.toLowerCase() === "allowedips") (acc.peers[publicKey]||(acc.peers[publicKey] = {})).allowedIPs = ([acc.peers[publicKey].allowedIPs, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
          else if (keyName.toLowerCase() === "presharedkey") (acc.peers[publicKey]||(acc.peers[publicKey] = {})).presharedKey = value;
          else if (keyName.toLowerCase() === "endpoint") (acc.peers[publicKey]||(acc.peers[publicKey] = {})).endpoint = value;
        }
      }
    }
    return acc;
  }, {} as any));
}