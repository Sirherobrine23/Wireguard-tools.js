import { wireguardInterface } from "../userspace";
function removeUndefined<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 *
 * @param wgConfig - Config string
 * @returns
 */
export function parseConfig(wgConfig: string|Buffer): wireguardInterface {
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
    peers: peersWG.reduce<wireguardInterface["peers"]>((acc, {data}) => {
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