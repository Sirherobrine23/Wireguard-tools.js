import path from "node:path";
import { LoadAddon, projectRoot } from "./addons.js";

export interface Peer {
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

export interface Config<T extends Peer = Peer> {
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

/**
 * Exported wireguard-tools.js addon
 */
export const addon = await LoadAddon<{
  /** External functions or drive info */
  constants: {
    /** Current Wireguard drive version */
    driveVersion?: string;
  }

  /**
   * Delete interface if exists
   * @param name - Interface name
   */
  deleteInterface(name: string): Promise<void>;

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
}>("wg", {
  WIN32DLLPATH: !process.env.WGWIN32DLL ? path.resolve(projectRoot, "addon/win", (process.arch === "x64" && "amd64") || (process.arch === "ia32" && "x86") || process.arch, "wireguard.dll") : path.resolve(process.env.WGWIN32DLL),
});

export const {
  constants: {driveVersion = "Unknown"},
  getConfig,
  setConfig,
  deleteInterface
} = addon;