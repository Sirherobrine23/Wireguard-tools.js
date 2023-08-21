import * as wgBinding from "./wg_binding";
import * as userspace from "./userspace";
import { wireguardInterface, peerConfig, WgError } from "./userspace";
export { wireguardInterface, peerConfig, WgError };

/**
 * List wireguard interface's in userspace and kernel (linux)
 *
 * @returns Devices name
 */
export async function listDevices() {
  if (process.platform !== "linux") return userspace.listDevices();
  return (await wgBinding.listDevices()).concat(...(await userspace.listDevices()))
}

/**
 * Get config wireguard config from wireguard interface
 * @param deviceName - Device name
 * @returns Config object
 */
export async function parseWgDevice(deviceName: string): Promise<wireguardInterface> {
  if (process.platform !== "linux") return userspace.parseWgDevice(deviceName);
  if ((await wgBinding.listDevices()).includes(deviceName)) return wgBinding.parseWgDevice(deviceName);
  return userspace.parseWgDevice(deviceName);
}

/**
 * Configure a Wireguard interface or even update it, if I was configuring it in linux, if it does not exist, it will create a new interface with the name
 *
 * @example
 * 
 * ```js
   await addDevice("wg0", {
    privateKey: "AAAAAAAAAAAAAAAAAAAA=",
    portListen: 8080,
    peers: {
      "GGGGAGGAGAGAGGAGGA=": {
        presharedKey: "googleInCloud==",
        allowedIPs: [
          "10.66.66.5/32",
          "10.66.45.2/32"
        ]
      }
    }
  });
 * ```
 *
 * @param deviceName - Wireguard interface name
 * @param interfaceConfig - Config to interface (if update get config with parseWgDevice)
 * @returns nothing
 */
export async function addDevice(deviceName: string, interfaceConfig: wireguardInterface) {
  if (process.platform !== "linux") return userspace.addDevice(deviceName, interfaceConfig);
  return wgBinding.addDevice(deviceName, interfaceConfig);
}