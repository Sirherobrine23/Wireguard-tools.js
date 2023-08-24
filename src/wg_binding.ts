import path from "path";
import { wireguardInterface } from "./userspace";
const wg_binding = require("../libs/prebuildifyLoad.cjs")("wginterface", path.join(__dirname, ".."));

export const constants: { MAX_NAME_LENGTH: number } = wg_binding.constants;

/**
 * List all Wireguard interfaces
 * @returns Interfaces array
 */
export async function listDevices(): Promise<string[]> {
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