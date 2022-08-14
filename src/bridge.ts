import * as os from "node:os";
const Bridge = require("node-gyp-build")(__dirname+"/..");

export type peerConfig = {
  presharedKey?: string,
  endpoint?: string,
  allowedIPs?: string[],
  rxBytes?: number,
  txBytes?: number,
  keepInterval?: number,
  lastHandshake?: Date,
};
export type wireguardInterface = {
  publicKey?: string,
  privateKey?: string,
  portListen?: number,
  Address?: string[],
  peers: {
    [peerPublicKey: string]: peerConfig
  }
};

/**
 * Get All Wireguard Interfaces with their Peers
 *
 * example:
 * ```json
  {
    "wg0": {
      "publicKey": "...",
      "privateKey": "...",
      "portListen": 51820,
      "peers": {
        "...": {
          "presharedKey": "...",
          "endpoint": "0.0.0.0:8888",
          "rxBytes": 1,
          "txBytes": 1,
          "lastHandshake": "2022-07-29T00:34:30.000Z"
        },
        "...2": {
          "presharedKey": "..."
        }
      }
    }
  }
  ```
 */
export function showAll(): {[interfaceName: string]: wireguardInterface} {
  const devices = Bridge.getDevices() as {[interfaceName: string]: wireguardInterface};
  for (const devname in devices) {
    if (os.networkInterfaces()[devname]) devices[devname].Address = os.networkInterfaces()[devname].map(link => link.address);
  }
  return devices;
}

/**
 * Get one Wireguard Interface with its Peers
 *
*/
export function show(wgName: string): wireguardInterface {
  const InterfaceInfo = Bridge.getDevice(wgName) as wireguardInterface;
  if (typeof InterfaceInfo === "string") throw new Error(InterfaceInfo);
  if (os.networkInterfaces()[wgName]) InterfaceInfo.Address = os.networkInterfaces()[wgName].map(link => link.address);
  return InterfaceInfo;
}

/**
 * Get only interfaces names
 */
export function getDeviceName() {return Object.keys(showAll());}

/**
 * Create Wireguard interface and return its name
 */
export function addDevice(interfaceConfig: wireguardInterface & {name: string}): wireguardInterface {
  // Check interface name
  if (!interfaceConfig.name) throw new Error("interface name is required");
  if (interfaceConfig.name.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfaceConfig.name)) throw new Error("interface name is invalid");
  if (showAll()[interfaceConfig.name]) throw new Error("interface name is already used");

  // Add interface
  const res = Bridge.addNewDevice(interfaceConfig);
  if (res === 0) return show(interfaceConfig.name);
  else if (res === -1) throw new Error("Unable to add device");
  else if (res === -2) throw new Error("Unable to set device");
  throw new Error("Add device error: "+res);
}

export function delDevice(interfacename: string): void {
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  if (!showAll()[interfacename]) throw new Error("interface name is not in use");
  const res = Bridge.delDevice(interfacename);
  if (res !== 0) throw new Error("Deleteinterface failed, return code: " + res);
  return;
}
