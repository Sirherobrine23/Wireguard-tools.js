import path from "node:path";
if (process.platform === "win32") {
  // Set dll path
  global["wireguardDllPath"] = path.join(__dirname, "addon/win32/bin", process.arch === "x64" ? "amd64" : process.arch === "ia32" ? "x88" : process.arch, "wireguard.dll");
}

interface Binding {
  listDevicesSync?(): any;
  parseWgDeviceSync?(wgName: string): any;
  setupInterfaceSync?(wgName: string, config: wireguardInterface): any;
}

const wg_binding: Binding = require("../libs/prebuildifyLoad.cjs")(__dirname+"/..", "wireguard_bridge");

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
  if (typeof wg_binding.listDevicesSync !== "function") throw new Error("Cannot list wireguard devices, check if avaible to current system!");
  return wg_binding.listDevicesSync();
}

/**
 * Get interface config.
 * @param deviceName - Wireguard interface name.
 * @returns
 */
export function parseWgDevice(deviceName: string): wireguardInterface {
  if (typeof wg_binding.parseWgDeviceSync !== "function") throw new Error("Cannot get device configs, check if wireguard is avaible to the system!");
  return wg_binding.parseWgDeviceSync(deviceName);
}

/**
 * Set Wireguard interface config.
 * @param deviceName - Wireguard interface name.
 * @param interfaceConfig - Peers and Interface config.
 */
export function addDevice(deviceName: string, interfaceConfig: wireguardInterface): void {
  if (typeof deviceName !== "string" || deviceName.length > 16 || deviceName.length <= 0) throw new Error("Check interface name!");
  wg_binding.setupInterfaceSync(deviceName, interfaceConfig);
}

export function removeInterface(deviceName: string): void {
  if (!((listDevices()).includes(deviceName))) throw new Error("Device not exists");
  // wg_binding.registerInterface(deviceName, false);
}