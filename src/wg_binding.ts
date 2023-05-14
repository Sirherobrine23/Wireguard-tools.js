const wg_binding = require("../libs/prebuildifyLoad.cjs")(__dirname+"/..", "wireguard_bridge");

export type peerConfig = {
  /** Mark this peer to be removed, any changes remove this option */
  removeMe?: boolean,
  presharedKey?: string,
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
  publicKey?: string,
  privateKey?: string,
  portListen?: number,
  Address?: string[],
  /** this option will remove all peers if `true` and add new peers */
  replacePeers?: boolean,
  peers: {
    [peerPublicKey: string]: peerConfig
  }
};

/**
 * List all Wireguard interfaces
 * @returns Interfaces array
 */
export function listDevices(): string[] {
  if (typeof wg_binding.listDevices !== "function") throw new Error("Cannot list wireguard devices, check if avaible to current system!");
  return wg_binding.listDevices();
}

/**
 * Get interface config.
 * @param deviceName - Wireguard interface name.
 * @returns
 */
export function parseWgDevice(deviceName: string): wireguardInterface {
  if (typeof wg_binding.parseWgDeviceV2 !== "function") throw new Error("Cannot get device configs, check if wireguard is avaible to the system!");
  return wg_binding.parseWgDeviceV2(deviceName);
}

/**
 * Set Wireguard interface config.
 * @param deviceName - Wireguard interface name.
 * @param interfaceConfig - Peers and Interface config.
 */
export function addDevice(deviceName: string, interfaceConfig: wireguardInterface): void {
  if (typeof deviceName !== "string" || deviceName.length > 16 || deviceName.length <= 0) throw new Error("Check interface name!");
  if (!((listDevices()).includes(deviceName))) {
    // Create interface
    wg_binding.registerInterface(deviceName, true);
  }
  wg_binding.setupInterface(deviceName, interfaceConfig);
}

export function removeInterface(deviceName: string): void {
  if (!((listDevices()).includes(deviceName))) throw new Error("Device not exists");
  wg_binding.registerInterface(deviceName, false);
}