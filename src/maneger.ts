import * as wginterface from "./wginterface.js"
import { publicKey, privateKey } from "./key.js"
import * as quick from "./quick.js"
import { isIP } from "net"

export class Wireguard extends Map<string, wginterface.Peer> {
  private _privateKey: string

  /** Current privateKey */
  get privateKey(): string {
    return this._privateKey
  }

  /** Get publicKey from privateKey */
  get publicKey(): string {
    if (!this._privateKey) throw new Error("Set private key to get publicKey")
    return publicKey(this._privateKey)
  }

  /** @deprecated set privateKey only */
  set publicKey(_key: string) {
    throw new Error("Set privateKey only")
  }

  /** Set interface privateKey */
  set privateKey(key: string) {
    this._privateKey = key
  }

  /** Generate privateKey to interface */
  async generatePrivateKey() {
    this._privateKey = await privateKey()
  }

  private _portListen: number
  get portListen() { return this._portListen; }
  set portListen(port: number) {
    if (port < 0 || port > 65534) throw new Error("Invalid port to listening");
    this._portListen = port
  }

  /** Get config */
  toJSON(wgName: string): wginterface.Config {
    const config: wginterface.Config = {
      name: wgName,
      portListen: this._portListen,
      privateKey: this.privateKey,
      peers: {},
    }
    for (const [publicKey, peerSettings] of this.entries()) {
      config.peers[publicKey] = {
        keepInterval: peerSettings.keepInterval,
        presharedKey: peerSettings.presharedKey,
        endpoint: peerSettings.endpoint,
        allowedIPs: peerSettings.allowedIPs
      }
    }
    return config;
  }

  /** Get quick config from current config */
  toString(extraConfig?: Omit<quick.QuickConfig, keyof wginterface.SetConfig>) {
    return quick.stringify(Object.assign({}, extraConfig, this.toJSON("wg0")))
  }

  /** Deploy config to wireguard interface */
  async deployConfig(wgName: string) {
    return wginterface.setConfig(this.toJSON(wgName))
  }

  /** Add peer to Map and check config */
  async addPeer(publicKey: string, peerConfig: wginterface.Peer) {
    if (peerConfig.allowedIPs?.length > 0) {
      for (const ipAddress of peerConfig.allowedIPs) if (isIP(ipAddress.split("/")[0]) === 0) throw new Error("Invalid ip address in allowedIPs")
    }
    peerConfig.keepInterval
    this.set(publicKey, peerConfig)
  }
}