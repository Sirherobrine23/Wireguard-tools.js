const { constants } = require("../wginterface");
const { randomInt } = require("node:crypto");
const net = require("node:net");
const ipManipulation = require("./ipm");
const keygen = require("./keygen");
module.exports = { parseConfig, createConfig };

/**
 * Create wg-quick config file
 * @param param0 - Config object input
 * @returns Config file string
 */
function createConfig({ portListen, publicKey, privateKey, Address, DNS, peers = {} }) {
  const configString = ["[Interface]"];
  if (typeof publicKey === "string" && publicKey.length === constants.WG_B64_LENGTH)
    configString.push(("PublicKey = ").concat(publicKey));
  if (typeof privateKey === "string" && privateKey.length === constants.WG_B64_LENGTH)
    configString.push(("PrivateKey = ").concat(privateKey));
  if (portListen >= 0 && portListen <= ((2 ** 16) - 1))
    configString.push(("ListenPort = ").concat(String(portListen)));
  if (Array.isArray(Address) && Address.length > 0)
    configString.push(("Address = ").concat(...(Address.join(", "))));
  if (Array.isArray(DNS) && DNS.length > 0)
    configString.push(("DNS = ").concat(DNS.join(", ")));
  // Peers mount
  for (const pubKey of Object.keys(peers)) {
    configString.push("", "[Peer]", ("PublicKey = ").concat(pubKey));
    const { presharedKey, allowedIPs, keepInterval, endpoint } = peers[pubKey];
    if (typeof presharedKey === "string" && presharedKey.length > 0)
      configString.push(("PresharedKey = ").concat(presharedKey));
    if (typeof endpoint === "string" && endpoint.length > 0)
      configString.push(("Endpoint = ").concat(endpoint));
    if (typeof keepInterval === "number" && keepInterval > 0)
      configString.push(("PersistentKeepalive = ").concat(String(keepInterval)));
    if (Array.isArray(allowedIPs) && allowedIPs.length > 0)
      configString.push(("AllowedIPs = ").concat(allowedIPs.join(", ")));
  }
  return configString.join("\n").trim();
}

/**
 * Parse wg-quick config and return config object
 * @param wgConfig - Config file
 * @returns Config object
 */
function parseConfig(wgConfig) {
  if (Buffer.isBuffer(wgConfig))
    wgConfig = wgConfig.toString();
  const lines = wgConfig.trim().split(/\r?\n/).map(s => s.trim()).filter(s => (!!s) && !(s.startsWith("#")));
  return Object.assign({}, { peers: {} }, lines.reduce((acc, line, index) => {
    if (line.toLowerCase() === "[peer]") {
      if (typeof acc.at(-1).start === "undefined")
        acc.at(-1).start = index;
      else {
        acc.at(-1).end = index - 1;
        acc.push({ start: index });
      }
    }
    return acc;
  }, [{ start: 0 }]).map(({ start, end }) => {
    const [target, ...linesConfig] = lines.slice(start, end);
    return {
      target: target.toLowerCase() === "[peer]" ? "peer" : "interface",
      linesConfig: linesConfig.map(s => {
        const ii = s.indexOf("="), keyName = s.substring(0, ii).trim(), value = s.substring(ii + 1).trim();
        return { keyName, value };
      })
    };
  }).reduce((acc, info) => {
    var _a;
    if (info.target === "interface") {
      for (const { keyName, value } of info.linesConfig) {
        if (keyName.toLowerCase() === "privatekey")
          acc.privateKey = value;
        else if (keyName.toLowerCase() === "publickey")
          acc.publicKey = value;
        else if (keyName.toLowerCase() === "address")
          acc.Address = ([acc.Address, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
        else if (keyName.toLowerCase() === "dns")
          acc.DNS = ([acc.DNS, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
        else if (keyName.toLowerCase() === "listenport") {
          const port = parseInt(value);
          if (port >= 1 && port <= ((2 ** 16) - 1))
            acc.portListen = port;
        }
      }
    }
    else if (info.target === "peer") {
      acc.peers = (acc.peers || {});
      const publicKey = (_a = info.linesConfig.find(s => s.keyName.toLowerCase() === "publickey")) === null || _a === void 0 ? void 0 : _a.value;
      if (!!publicKey) {
        for (const { keyName, value } of info.linesConfig) {
          if (keyName.toLowerCase() === "publickey")
            continue;
          else if (keyName.toLowerCase() === "allowedips")
            (acc.peers[publicKey] || (acc.peers[publicKey] = {})).allowedIPs = ([acc.peers[publicKey].allowedIPs, value]).flat(3).map(s => s && s.split(",")).flat(2).map(s => s && s.trim()).filter(Boolean);
          else if (keyName.toLowerCase() === "presharedkey")
            (acc.peers[publicKey] || (acc.peers[publicKey] = {})).presharedKey = value;
          else if (keyName.toLowerCase() === "endpoint")
            (acc.peers[publicKey] || (acc.peers[publicKey] = {})).endpoint = value;
        }
      }
    }
    return acc;
  }, {}));
}

class wgConfig extends Map {
  privateKey;
  publicKey;
  #portListen;

  get portListen() { return this.#portListen||0; }
  set portListen(portListen) {
    if (portListen >= 0 && portListen <= ((2 ** 16) - 1)) this.#portListen = portListen;
    else throw new Error("Invalid port listen");
  }

  #fwmark;
  get fwmark() {
    this.#fwmark = (parseInt(String(this.#fwmark))||0);
    if (this.#fwmark < 0) this.#fwmark = 0;
    return this.#fwmark;
  }
  set fwmark(fwmark) {
    if (fwmark >= 0) this.#fwmark = fwmark;
    else throw new Error("Set valid fwmark");
  }

  #replacePeers = true;
  get replacePeers() { return !!(this.#replacePeers); }
  set replacePeers(replace) { this.#replacePeers = !!replace; }

  Address = [];
  DNS = [];

  constructor(config) {
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

  async newPeer(withPreshared) {
    let peerKey;
    while (!peerKey) {
      peerKey = await keygen.keygen(withPreshared);
      if (this.has(peerKey.publicKey)) peerKey = undefined;
    }
    if (!(Array.isArray(this.Address))) throw new Error("Invalid config");
    const cidrIPv4 = this.Address.filter(s => net.isIPv4(s.split("/")[0]));
    if (cidrIPv4.length === 0) throw new Error("Set Interface IPv4 subnet");
    const allowedIPs = Array.from(this.values()).map(s => (s||{}).allowedIPs).flat(2).filter(s => typeof s === "string" && net.isIPv4(s.split("/")[0]));
    const Addr = cidrIPv4.at(cidrIPv4.length === 1 ? 0 : randomInt(0, cidrIPv4.length - 1));
    const IPv4 = ipManipulation.nextIpSequence(Addr, [Addr, ...allowedIPs]), IPv6 = ipManipulation.toV6(IPv4, true);
    this.set(peerKey.publicKey, {
      privateKey: peerKey.privateKey,
      presharedKey: withPreshared ? peerKey.presharedKey : undefined,
      allowedIPs: [IPv4, IPv6],
    });
    return Object.assign({}, { publicKey: peerKey.publicKey }, this.get(peerKey.publicKey));
  }

  /**
   * Get peer config
   * @param publicKey - Peer public key
   * @param remoteAddress - ip or hostname to server, example: 123.456.789.101, [::ffff:24bd:34ac]
   * @returns
   */
  async getClientConfig(publicKey, remoteAddress) {
    if (!(this.has(publicKey))) throw new Error("Set valid public key");
    const { presharedKey, privateKey, allowedIPs } = this.get(publicKey);
    if (!(typeof privateKey === "string" && privateKey.length >= 44)) throw new Error("Peer not set private key to add in interface");
    const endpoint = remoteAddress.concat(":", String(Math.floor(this.portListen)));
    return {
      privateKey: privateKey,
      Address: allowedIPs,
      DNS: Array.from(new Set(([...this.DNS]).map(s => s.split("/")[0]))),
      peers: {
        [await keygen.genPublic(this.privateKey)]: {
          presharedKey,
          endpoint,
          allowedIPs: [
            "0.0.0.0/0",
            "::/0"
          ]
        }
      }
    };
  }

  /** Get server config JSON */
  getServerConfig() {
    const { Address, portListen, privateKey, fwmark } = this;
    return Array.from(this.entries()).reduce((acc, [publicKey, {presharedKey, allowedIPs}]) => {
      acc.peers[publicKey] = { presharedKey, allowedIPs };
      return acc;
    }, { Address, portListen, privateKey, fwmark, peers: {} });
  }

  toJSON() {
    const { privateKey, publicKey, portListen, replacePeers, fwmark, Address, DNS } = this;
    return (Array.from(this.entries()).reduce((acc, [pubKey, { presharedKey, privateKey, endpoint, keepInterval, removeMe, allowedIPs }]) =>  {
      acc.peers[pubKey] = {
        ...(!!presharedKey ? {presharedKey}:{}),
        ...(!!privateKey ? {privateKey}:{}),
        ...(!!endpoint ? {endpoint}:{}),
        ...(!!keepInterval ? {keepInterval}:{}),
        ...(!!removeMe ? {removeMe}:{}),
        ...(!!allowedIPs ? {allowedIPs}:{})
      };
      return acc;
    }, {
      ...(!!privateKey ? {privateKey}:{}),
      ...(!!publicKey ? {publicKey}:{}),
      ...(!!portListen ? {portListen}:{}),
      ...(!!fwmark ? {fwmark}:{fwmark: 0}),
      ...(!!replacePeers ? {replacePeers}:{}),
      ...(!!Address ? {Address}:{}),
      ...(!!DNS ? {DNS}:{}),
      peers: {}
    }));
  }

  toString() {
    return createConfig(this.toJSON());
  }
}

module.exports.wgConfig = wgConfig;