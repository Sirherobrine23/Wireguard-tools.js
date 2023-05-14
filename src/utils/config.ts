export type wireguardConfig = {
  publicKey?: string;
  privateKey?: string;
  portListen?: number;
  Address?: string[];
  DNS?: string[];
  peers: {
    [peerPublicKey: string]: {
      presharedKey?: string;
      keepInterval?: number;
      endpoint?: string;
      allowedIPs?: string[];
    };
  }
};

function removeUndefined<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 *
 * @param wgConfig - Config string
 * @returns
 */
export function parseConfig(wgConfig: string|Buffer): wireguardConfig {
  if (Buffer.isBuffer(wgConfig)) wgConfig = wgConfig.toString();
  wgConfig = wgConfig.trim().split("\r\n").join("\n");
  let strs: string[] = [];
  while (wgConfig.length > 0) {
    const newI = wgConfig.lastIndexOf("[");
    strs = ([wgConfig.slice(newI).trim()]).concat(...strs);
    wgConfig = wgConfig.slice(0, newI);
  }
  const maps = strs.map(str => {
    const type = str.slice(0, 11).toLowerCase() === "[interface]" ? "Interface" : "Peer";
    const data = str.slice(type === "Interface" ? 11 : 6).trim();
    const rawObj = data.split("\n").reduce<{[key: string]: string[]}>((acc, line) => {
      const index = line.indexOf("=");
      const key = line.slice(0, index).trim().toLowerCase();
      acc[key] ||= [];
      acc[key].push(line.slice(index+1).trim());
      return acc;
    }, {});
    return {
      type,
      data: Object.keys(rawObj).map(keyName => {
        if (keyName === "allowedips" || keyName === "address" || keyName === "dns") return {keyName, data: rawObj[keyName].map(s => s.split(",").map(s => s.trim())).flat(2)};
        else return {keyName, data: rawObj[keyName].at(0)};
      }).reduce((acc, config) => {
        acc[config.keyName] = config.data;
        return acc;
      }, {})
    };
  });
  const interfaceWG = maps.filter(s => s.type === "Interface").at(0)?.data;
  if (!interfaceWG) throw new Error("Invalid config file");
  const peersWG = maps.filter(s => s.type !== "Interface");
  return removeUndefined({
    portListen: interfaceWG["listenport"] ? Number(interfaceWG["listenport"]) : undefined,
    privateKey: interfaceWG["privatekey"],
    publicKey: interfaceWG["publickey"],
    DNS: interfaceWG["dns"],
    Address: interfaceWG["address"],
    peers: peersWG.reduce<wireguardConfig["peers"]>((acc, {data}) => {
      acc[data["publickey"]] = {
        presharedKey: data["presharedkey"],
        keepInterval: data["keepinterval"] ? Number(data["keepinterval"]) : undefined,
        endpoint: data["endpoint"],
        allowedIPs: data["allowedips"],
      };
      return acc;
    }, {})
  });
}

/**
 * Create wireguard config string.
 */
export function createConfig(config: wireguardConfig) {
  let configString: string = "[Interface]\n";
  if (typeof config.publicKey === "string" && config.publicKey.length > 0) configString += ("PublicKey = "+config.publicKey) + "\n";
  if (typeof config.privateKey === "string" && config.privateKey.length > 0) configString += ("PrivateKey = "+config.privateKey) + "\n";
  if (typeof config.portListen === "number" && (config.portListen > 0 && config.portListen < 25565)) configString += ("ListenPort = "+config.portListen) + "\n";
  if (Array.isArray(config.Address) && config.Address.length > 0) configString += ("Address = "+config.Address.join(", ")) + "\n";
  if (Array.isArray(config.DNS) && config.DNS.length > 0) configString += ("DNS = "+config.DNS.join(", ")) + "\n";
  configString += "\n";
  for (const pubKey of Object.keys(config.peers)) {
    configString += ("[Peer]\nPublicKey = "+pubKey) + "\n";
    const peerConfig = config.peers[pubKey];
    if (typeof peerConfig.presharedKey === "string" && peerConfig.presharedKey.length > 0) configString += ("PresharedKey = " + peerConfig.presharedKey) + "\n";
    if (typeof peerConfig.endpoint === "string" && peerConfig.endpoint.length > 0) configString += ("Endpoint = " + peerConfig.endpoint) + "\n";
    if (typeof peerConfig.keepInterval === "number" && peerConfig.keepInterval > 0) configString += ("PersistentKeepalive = " + peerConfig.keepInterval) + "\n";
    if (Array.isArray(peerConfig.allowedIPs) && peerConfig.allowedIPs.length > 0) configString += ("AllowedIPs = " + peerConfig.allowedIPs.join(", ")) + "\n";
  }

  return configString.trim();
}