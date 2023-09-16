export type Constants = {
  WG_B64_LENGTH: number;
  MAX_NAME_LENGTH: number;
  driveVersion: string;
};

export const constants: Constants;

export type peerConfig = {
  /** Mark this peer to be removed, any changes remove this option */
  removeMe?: boolean,
  presharedKey?: string,
  privateKey?: string,
  keepInterval?: number,
  /** Remote address or hostname to Wireguard connect */
  endpoint?: string,
  /** Accept connection from this address */
  allowedIPs?: string[],
  rxBytes?: number,
  txBytes?: number,
  lastHandshake?: Date,
};

export type wireguardInterface = {
  publicKey?: string;
  privateKey?: string;
  portListen?: number;
  fwmark?: number;
  Address?: string[];
  DNS?: string[];
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean;
  peers: {
    [peerPublicKey: string]: peerConfig;
  }
};


export function listDevices(): {from: "userspace"|"kernel", name: string, path?: string}[];
export function getConfig(deviceName: string): Promise<wireguardInterface>;
export function deleteInterface(deviceName: string): Promise<void>
export function setConfig(deviceName: string, interfaceConfig: wireguardInterface): Promise<void>;