import path from "node:path";
import { loadAddon } from "rebory";
import { key } from "./index.js";
import { isIP } from "node:net";
const __dirname = import.meta.dirname || path.dirname((await import("node:url")).fileURLToPath(import.meta.url));

interface Peer {
  /** Preshared key to peer */
  presharedKey?: string;

  /** keepInterval specifies the persistent keepalive interval for this peer */
  keepInterval?: number;

  /** Remote address or hostname to Wireguard connect or endpoint is the most recent source address used for communication by peer. */
  endpoint?: string;

  /** AllowedIPs specifies a list of allowed IP addresses in CIDR notation (`0.0.0.0/0`, `::/0`) */
  allowedIPs?: string[];
};

export interface SetPeer extends Peer {
  /** Remove this peer */
  removeMe?: boolean;
}

export interface GetPeer extends Peer {
  /** ReceiveBytes indicates the number of bytes received from this peer. */
  rxBytes: bigint;

  /** TransmitBytes indicates the number of bytes transmitted to this peer. */
  txBytes: bigint;

  /** Last peer Handshake */
  lastHandshake: Date;
}

interface Config<T extends Peer> {
  /** Wireguard interface name */
  name: string;

  /** privateKey specifies a private key configuration */
  privateKey: string;

  /** publicKey specifies a public key configuration */
  publicKey?: string;

  /** ListenPort specifies a device's listening port, 0 is random */
  portListen?: number;

  /** FirewallMark specifies a device's firewall mark */
  fwmark?: number;

  /** Interface IP address'es */
  address?: string[];

  /** Interface Peers */
  peers: Record<string, T>;
};

export interface GetConfig extends Config<GetPeer> { };
export interface SetConfig extends Config<SetPeer> {
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean;
};

export const addon = (await loadAddon(path.resolve(__dirname, "../binding.yaml"))).wginterface.load_addon<{
  /** Current Wireguard drive version */
  driveVersion?: string;

  /**
   * Delete interface if exists
   * @param name - Interface name
   */
  deleteInterface(name: string): Promise<void>;

  /**
   * Get Wireguard interfaces list
   *
   * if running in userspace return socket (UAPI) path's
   */
  listDevices(): Promise<string[]>;

  /**
   * Get current config from Wireguard interface
   * @param name - Interface name
   */
  getConfig(name: string): Promise<GetConfig>;

  /**
   * Set new config to Wireguard interface or create new interface if not exists
   * @param config - Interface config
   */
  setConfig(config: SetConfig): Promise<void>;
}>({
  WIN32DLLPATH: path.resolve(__dirname, "../addon/win", (process.arch === "x64" && "amd64") || (process.arch === "ia32" && "x86") || process.arch, "wireguard.dll")
});

export const {
  driveVersion,
  listDevices,
  getConfig,
  setConfig,
  deleteInterface
} = addon;

export class WireGuardPeer {
  constructor(public publicKey: string, private __Wg: Wireguard) { }

  async getStats() {
    const { rxBytes, txBytes, lastHandshake } = await getConfig(this.__Wg.name).then((config) => config.peers[this.publicKey]);
    return {
      rxBytes,
      txBytes,
      lastHandshake
    };
  }

  addNewAddress(address: string) {
    if (isIP(address.split("/")[0]) === 0) throw new Error("Invalid IP address");
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    const _addr = new Set(this.__Wg._peers.get(this.publicKey).allowedIPs);
    _addr.add(address.split("/")[0]);
    this.__Wg._peers.get(this.publicKey).allowedIPs = Array.from(_addr);
    return this;
  }

  removeAddress(address: string) {
    if (isIP(address.split("/")[0]) === 0) throw new Error("Invalid IP address");
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    const _addr = new Set(this.__Wg._peers.get(this.publicKey).allowedIPs);
    _addr.delete(address.split("/")[0]);
    this.__Wg._peers.get(this.publicKey).allowedIPs = Array.from(_addr);
    return this;
  }

  setKeepInterval(keepInterval: number) {
    if (typeof keepInterval !== "number" || keepInterval < 0) throw new Error("Invalid keepInterval");
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    if (keepInterval > 0) this.__Wg._peers.get(this.publicKey).keepInterval = keepInterval;
    else delete this.__Wg._peers.get(this.publicKey).keepInterval;
    return this;
  }

  setEndpoint(endpoint: string) {
    if (typeof endpoint !== "string") throw new Error("Invalid endpoint");
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    if (endpoint.length > 0) this.__Wg._peers.get(this.publicKey).endpoint = endpoint;
    else delete this.__Wg._peers.get(this.publicKey).endpoint;
    return this;
  }

  /**
   * Sets the preshared key for the peer.
   * @param presharedKey - The preshared key to set. If not provided, a new preshared key will be generated.
   * @returns The updated WireGuard interface object.
   * @throws {Error} If the provided preshared key is invalid.
   */
  setPresharedKey(): Promise<this> & this;
  /**
   * Sets the preshared key for the peer.
   * @param presharedKey - The preshared key to set. If not provided, a new preshared key will be generated.
   * @returns The updated WireGuard interface object.
   * @throws {Error} If the provided preshared key is invalid.
   */
  setPresharedKey(presharedKey: string): this;
  /**
   * Sets the preshared key for the peer.
   * @param presharedKey - The preshared key to set. If not provided, a new preshared key will be generated.
   * @returns The updated WireGuard interface object.
   * @throws {Error} If the provided preshared key is invalid.
   */
  setPresharedKey(presharedKey?: string) {
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    if (!presharedKey) return Object.assign(key.presharedKey().then((presharedKey) => this.__Wg._peers.get(this.publicKey).presharedKey = presharedKey), this);
    if (typeof presharedKey !== "string" || presharedKey.length !== key.Base64Length) throw new Error("Invalid presharedKey");
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    this.__Wg._peers.get(this.publicKey).presharedKey = presharedKey;
    return this;
  }

  /**
   * Removes the peer from the WireGuard interface.
   * @returns The updated WireGuard interface.
   */
  remove() {
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    this.__Wg._peers.get(this.publicKey)["removeMe"] = true;
    return this;
  }

  /**
   * Converts the `WireGuard Peer` object to a JSON representation.
   * @returns The JSON representation of the `WireGuard Peer` object.
   */
  toJSON(): [string, SetPeer] {
    if (!this.__Wg._peers) this.__Wg._peers = new Map();
    const { keepInterval, endpoint, presharedKey, allowedIPs } = this.__Wg._peers.get(this.publicKey);
    const peer: SetPeer = Object.create({});
    if (presharedKey) peer.presharedKey = presharedKey;
    if (keepInterval) peer.keepInterval = keepInterval;
    if (endpoint) peer.endpoint = endpoint;
    if (allowedIPs) peer.allowedIPs = allowedIPs;
    return [this.publicKey, peer];
  }
}

/**
 * Maneger Wireguard interface and peers simple and fast
 */
export class Wireguard {
  constructor(config?: SetConfig | GetConfig | Config<Peer>) {
    // super({});
    if (!config) return;
    if (typeof config === "object") {
      if (config instanceof Wireguard) return config;
    }
  }

  private _name: string;
  get name() {
    return this._name;
  }

  /**
   * Set Wireguard interface name
   * @param name - Interface name
   * @returns Wireguard
   */
  set name(name: string) {
    if (typeof name !== "string" || name.length === 0) throw new Error("Invalid name");
    this._name = name;
  }

  private _portListen: number;
  /**
   * Sets the port to listen on.
   * @param port - The port number to listen on.
   * @returns The current instance of the `Wireguard` class.
   * @throws {Error} If the provided port is not a number or is less than 0.
   */
  setPortListen(port: number) {
    if (typeof port !== "number" || port < 0) throw new Error("Invalid port");
    this._portListen = port;
    return this;
  }

  private _fwmark: number;

  /**
   * Sets the fwmark value for the WireGuard interface.
   *
   * @param fwmark - The fwmark value to set.
   * @returns The current instance of the `Wireguard` class.
   * @throws {Error} If the `fwmark` value is not a number or is less than 0.
   */
  setFwmark(fwmark: number) {
    if (typeof fwmark !== "number" || fwmark < 0) throw new Error("Invalid fwmark");
    this._fwmark = fwmark;
    return this;
  }

  private _privateKey: string;

  /**
   * Get interface public key
   */
  public get publicKey() {
    return key.publicKey(this._privateKey);
  }

  /**
   * Generate new private key and set to Wireguard interface
   */
  setPrivateKey(): Promise<this> & this;
  /**
   * Set private key to Wireguard interface
   * @param privateKey - Private key
   * @returns Wireguard
   */
  setPrivateKey(privateKey: string): this;
  setPrivateKey(privateKey?: string): this {
    if (!privateKey) return Object.assign(key.privateKey().then((privateKey) => this._privateKey = privateKey), this);
    else this._privateKey = privateKey;
    return this;
  }

  private _address: string[];

  addNewAddress(address: string) {
    if (isIP(address.split("/")[0]) === 0) throw new Error("Invalid IP address");
    const _addr = new Set(this._address);
    _addr.add(address.split("/")[0]);
    this._address = Array.from(_addr);
    return this;
  }

  removeAddress(address: string) {
    if (isIP(address.split("/")[0]) === 0) throw new Error("Invalid IP address");
    const _addr = new Set(this._address);
    _addr.delete(address.split("/")[0]);
    this._address = Array.from(_addr);
    return this;
  }

  _peers: Map<string, Peer>;

  /**
   * Adds a new peer to the Wireguard interface.
   *
   * @param publicKey - The public key of the peer.
   * @param peer - other configuration options for the peer.
   * @throws Error if the peer is invalid.
   */
  addNewPeer(publicKey: string, peer: Peer) {
    if (!this._peers) this._peers = new Map();
    if (!((typeof publicKey === "string" && publicKey.length === key.Base64Length) && typeof peer === "object")) throw new Error("Invalid peer");
    let { allowedIPs, endpoint, keepInterval, presharedKey } = peer;
    this._peers.set(publicKey, {});
    if ((typeof presharedKey === "string" && presharedKey.length === key.Base64Length)) this._peers.get(publicKey).presharedKey = presharedKey;
    if (typeof keepInterval === "number") this._peers.get(publicKey).keepInterval = keepInterval;
    if (typeof endpoint === "string") this._peers.get(publicKey).endpoint = endpoint;
    if (Array.isArray(allowedIPs)) this._peers.get(publicKey).allowedIPs = allowedIPs.filter((ip) => isIP(ip.split("/")[0]) !== 0);
    return new WireGuardPeer(publicKey, this);
  }

  /**
   * Removes a peer from the WireGuard interface.
   * @param publicKey - The public key of the peer to remove.
   * @returns The updated WireGuard interface.
   */
  removePeer(publicKey: string) {
    if (this._peers) this._peers.delete(publicKey);
    return this;
  }



  /**
   * Converts the `Wireguard Interface` object to a JSON representation.
   * @returns The JSON representation of the `Wireguard Interface` object.
   */
  toJSON(): SetConfig {
    const config: SetConfig = Object.create({});
    config.name = this._name;
    config.privateKey = this._privateKey;
    if (this._portListen) config.portListen = this._portListen;
    if (this._fwmark) config.fwmark = this._fwmark;
    if (this._address) config.address = this._address;
    if (this._peers) config.peers = Array.from(this._peers||[]).map(([pubKey]) => new WireGuardPeer(pubKey, this).toJSON()).reduce((obj, [pubKey, peer]) => (obj[pubKey] = peer, obj), {});
    return config;
  }

  /**
   * Set new config to Wireguard interface or create new interface if not exists
   * @returns Promise<void>
   */
  async deploy() {
    return setConfig({
      ...(this.toJSON()),
      replacePeers: true,
    });
  }

  /**
   * Deletes the WireGuard interface.
   * @returns A promise that resolves when the interface is successfully deleted.
   */
  async delete() {
    return deleteInterface(this._name);
  }

  /**
   * Retrieves the configuration for the Wireguard interface.
   */
  async getConfig() {
    const { peers, privateKey, address, fwmark, portListen } = await getConfig(this._name);
    this._privateKey = privateKey;
    this._portListen = portListen;
    this._address = address;
    this._fwmark = fwmark;

    this._peers = new Map(Object.entries(peers));
    for (const [publicKey, { allowedIPs, endpoint, keepInterval, presharedKey }] of this._peers) {
      this._peers.set(publicKey, { allowedIPs, endpoint, keepInterval, presharedKey });
      if (keepInterval === 0) delete this._peers.get(publicKey).keepInterval;
      if (!presharedKey) delete this._peers.get(publicKey).presharedKey;
      if (!endpoint) delete this._peers.get(publicKey).endpoint;
      if (!allowedIPs) delete this._peers.get(publicKey).allowedIPs;
      else if (allowedIPs.length === 0) delete this._peers.get(publicKey).allowedIPs;
    }
  }
}
export default Wireguard;