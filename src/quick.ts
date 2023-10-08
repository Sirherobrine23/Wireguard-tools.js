import { isIP } from "net";
import { WgConfig, constants } from "./wginterface";
import { genKey, publicKey, keyObjectWithPreshared } from "./key";
import { randomInt } from "crypto";

export interface QuickConfig extends WgConfig {
  DNS?: string[];
}

export function parse(config: string|Buffer): QuickConfig {
  if (Buffer.isBuffer(config)) config = config.toString();
  const lines = config.trim().split(/\r?\n/).map(s => s.trim()).filter(s => (!!s) && !(s.startsWith("#")));
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
  }).reduce<QuickConfig>((acc, info) => {
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

export function stringify({ portListen = 0, privateKey, publicKey, Address, DNS = [ "1.1.1.1", "8.8.8.8" ], peers = {} }: QuickConfig): string {
  const configString: string[] = ["[Interface]"];
  if (typeof publicKey === "string" && publicKey.length === constants.WG_B64_LENGTH) configString.push(("PublicKey = ").concat(publicKey));
  if (typeof privateKey === "string" && privateKey.length === constants.WG_B64_LENGTH) configString.push(("PrivateKey = ").concat(privateKey));
  if (portListen >= 0 && portListen <= ((2 ** 16) - 1)) configString.push(("ListenPort = ").concat(String(portListen)));
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
 * Create and Manipulate interface Configs
 */
export class WgQuick extends Map<string, QuickConfig["peers"][string]> {
  private _privateKey: string;

  /**
   * Set private key to interface
   */
  set privateKey(key: string) {
    if (key.length === constants.WG_B64_LENGTH) {
      this._privateKey = key;
      publicKey(key).then(key => this._publicKey = key, () => {});
    }
    else throw new Error("Invalid private key");
  }

  /**
   * Get private key from interface config
   */
  get privateKey(): string|undefined {
    if (String(this._privateKey).length === constants.WG_B64_LENGTH) return this._privateKey;
    return undefined;
  }

  private _publicKey: string;
  /**
   * Set public key to interface
   */
  set publicKey(key: string) {
    if (key.length === constants.WG_B64_LENGTH) this._publicKey = key;
    else throw new Error("Invalid public key");
  }

  /**
   * Get public key from interface config
   */
  get publicKey(): string|undefined {
    if (String(this._publicKey).length === constants.WG_B64_LENGTH) return this._publicKey;
    return undefined;
  }

  private _portListen: number = randomInt(2000, 65535);
  /** Get port to listen, 0 less a 65535 */
  set portListen(port: number) {
    if (port >= 1 && port <= 65535) this._portListen = port;
    else if (port === 0) this._portListen = (port = randomInt(2000, 65535));
    else throw new Error("Set valid range port 0 to or equal at a 65535");
  }

  get portListen() {
    if (this._portListen <= 0) return (this._portListen = randomInt(2000, 65535));
    return this._portListen||0;
  }

  private _Address: string[] = [ "10.0.0.1/24" ];
  get Address() {
    return this._Address||[];
  }

  set Address(addr: string[]) {
    this._Address = Array.isArray(addr) ? addr.filter(s => !!(isIP(s.split("/")[0]))) : [];
  }

  private _DNS: string[] = [ "1.1.1.1", "8.8.8.8" ];
  get DNS() { return this._DNS||[]; }
  set DNS(dns: string[]) {
    this._DNS = Array.isArray(dns) ? dns.filter(s => !!(isIP(s.split("/")[0]))) : [];
  }

  constructor(config?: QuickConfig) {
    super();
    if (!config) return;
    const {
      privateKey, publicKey,
      portListen,
      Address, DNS,
      peers
    } = config;
    this._portListen = portListen;
    this.privateKey = privateKey;
    this._publicKey = publicKey;
    this.Address = Array.isArray(Address) ? Address.filter(s => !!(isIP(s.split("/")[0]))) : [];
    this.DNS = Array.isArray(DNS) ? DNS.filter(s => !!(isIP(s))) : [];
    for (const pubKey in (peers||{})) if (pubKey.length === constants.WG_B64_LENGTH && peers[pubKey]) this.set(pubKey, peers[pubKey]);
  }

  /**
   * Generate peer base keys and return public key to set remaining of config's.
   * @param preshareKey - Generate peer with Preshared key
   */
  set(preshareKey?: boolean): Promise<string>;

  /**
   * Generate keys and return Promise with all Public keys generated
   * @param keys - Keys to generate
   * @param preshareKey - Peers with preshared key
   */
  set(keys: number, preshareKey?: boolean): Promise<string[]>;

  /**
   * Set peer config
   * @param key - Peer public key
   * @param value - Peer config
   */
  set(key: string, value: QuickConfig["peers"][string]): this;
  set() {
    if (arguments.length === 0 || typeof arguments[0] === "boolean" || typeof arguments[0] === "number") {
      let preshareKey = !!arguments[1];
      if (typeof arguments[0] === "number") {
        if (!(arguments[0] > 0)) throw new Error("Set less 1 or equal");
        return Promise.all(Array(arguments[0]).fill(undefined).map(async () => this.set(preshareKey)));
      }

      preshareKey = !!arguments[0];
      return Promise.resolve().then(async () => {
        let peerKey: keyObjectWithPreshared;
        while (!peerKey) {
          peerKey = await genKey(true);
          if (this.has(peerKey.publicKey)) peerKey = undefined;
        }
        super.set(peerKey.publicKey, {
          ...(preshareKey ? { presharedKey: peerKey.presharedKey } : {}),
          keepInterval: 5,
          allowedIPs: [],
        });

        return peerKey.publicKey;
      });
    }

    if (String(arguments[0]||"").length !== constants.WG_B64_LENGTH) throw new Error("Set valid peer public key!");
    const { allowedIPs = [], endpoint, keepInterval = 0, presharedKey } = (arguments[1]||{}) as QuickConfig["peers"][string];
    super.set(arguments[0], {
      ...(String(presharedKey||"").length === constants.WG_B64_LENGTH ? { presharedKey } : {}),
      ...(String(endpoint||"").length >= 1 ? { endpoint } : {}),
      keepInterval,
      allowedIPs,
    });
    return this;
  }

  toJSON(): QuickConfig {
    const { _privateKey, _publicKey, _Address, _DNS, _portListen } = this;
    return {
      ...(_privateKey ? { privateKey: _privateKey } : {}),
      ...(_publicKey ? { publicKey: _publicKey } : {}),
      ...(_Address ? { Address: _Address } : { Address: [] }),
      portListen: _portListen,
      ...(_DNS ? { DNS: _DNS } : { DNS: [] }),
      peers: Array.from(this.entries()).reduce<QuickConfig["peers"]>((acc, [pubKey, config]) => Object.assign(acc, {[pubKey]: config}), {}),
    };
  }

  toString() {
    return stringify(this.toJSON());
  }
}