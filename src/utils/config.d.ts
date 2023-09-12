import { wireguardInterface, peerConfig } from "../wginterface";

/**
 * Create wg-quick config file
 * @param param0 - Config object input
 * @returns Config file string
 */
export declare function createConfig({ portListen, publicKey, privateKey, Address, DNS, peers }: wireguardInterface): string;

/**
 * Parse wg-quick config and return config object
 * @param wgConfig - Config file
 * @returns Config object
 */
export declare function parseConfig(wgConfig: string | Buffer): wireguardInterface;

export class wgConfig extends Map<string, peerConfig> {
  privateKey?: string;
  publicKey: string;
  portListen?: number;
  replacePeers: boolean;
  Address: string[];
  DNS: string[];
  constructor(config?: wireguardInterface);

  newPeer(withPreshared?: boolean): Promise<{publicKey: string} & peerConfig>;
  getClientConfig(publicKey: string, remoteAddress: string): Promise<wireguardInterface>

  getServerConfig(): wireguardInterface;
  toJSON(): wireguardInterface;
  toString(): string;
}