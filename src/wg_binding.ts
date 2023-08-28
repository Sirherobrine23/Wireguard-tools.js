import path from "path";
import { wireguardInterface } from "./userspace";
import { promisify } from "util";
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
export async function parseWgDevice(deviceName: string): Promise<wireguardInterface> {
  if (typeof wg_binding.getConfigAsync !== "function") throw new Error("Cannot get device configs, check if wireguard is avaible to the system!");
  return promisify(wg_binding.getConfigAsync)(deviceName);
}

/**
 * Set Wireguard interface config.
 * @param deviceName - Wireguard interface name.
 * @param interfaceConfig - Peers and Interface config.
 */
export async function addDevice(deviceName: string, interfaceConfig: wireguardInterface): Promise<void> {
  if (typeof deviceName !== "string" || deviceName.length > 16 || deviceName.length <= 0) throw new Error("Check interface name!");
  return promisify(wg_binding.setConfigAsync)(deviceName, interfaceConfig);
}