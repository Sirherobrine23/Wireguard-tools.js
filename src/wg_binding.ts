const wg_binding = require("node-gyp-build")(__dirname+"/..");
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
  const devices = wg_binding.getDevices() as {[interfaceName: string]: wireguardInterface};
  return devices;
}

/**
 * Get one Wireguard Interface with its Peers
 *
*/
export function show(wgName: string): wireguardInterface {
  const InterfaceInfo = wg_binding.getDevice(wgName) as wireguardInterface;
  if (typeof InterfaceInfo === "string") throw new Error(InterfaceInfo);
  return InterfaceInfo;
}

/**
 * Get only interfaces names
 */
export function getDeviceName() {return Object.keys(showAll());}

export function removeInterface(interfaceName: string): void {
  // Check interface name
  if (!interfaceName) throw new Error("interface name is required");
  if (interfaceName.length >= 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfaceName)) throw new Error("interface name is invalid");
  if (!showAll()[interfaceName]) return;
  const res = wg_binding.removeInterface(interfaceName);
  if (res !== 0) throw new Error("Delete interface failed, return code: " + res);
  return;
}

/**
 * Create Wireguard interface and return its name
 */
export function addDevice(interfaceName: string, interfaceConfig: wireguardInterface): wireguardInterface {
  // Check interface name
  if (!interfaceName) throw new Error("interface name is required");
  if (interfaceName.length >= 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfaceName)) throw new Error("interface name is invalid");
  const addInterfaceResult = wg_binding.addInterface(interfaceName);
  if (addInterfaceResult === -17) {
    if (interfaceConfig.replacePeers === undefined) {
      console.info("Replacing peers to %s.", interfaceName);
      interfaceConfig.replacePeers = true;
    }
  } else if (addInterfaceResult !== 0) throw new Error("Create interface failed, return code: " + addInterfaceResult);

  // Remove peers with removeMe option
  if (interfaceConfig.replacePeers === true) {
    for (const peerPublicKey in interfaceConfig.peers) {
      if (interfaceConfig.peers[peerPublicKey].removeMe === true) delete interfaceConfig.peers[peerPublicKey];
    }
  }

  // Add interface
  const res = wg_binding.setupInterface(interfaceName, interfaceConfig);
  if (res === 0) return show(interfaceName);
  throw new Error("Add device error: "+res);
}

export function peerOperation(interfaceName: string, operation: "delete"|"add"|"replace", publicKey: string, config: peerConfig) {
  const currentConfig = show(interfaceName);
  if (operation === "delete") {
    if (!currentConfig.peers[publicKey]) throw new Error("Peer not found");
    currentConfig.peers[publicKey].removeMe = true;
  } else if (operation === "add") {
    if (currentConfig.peers[publicKey]) throw new Error("Peer already exists");
    currentConfig.peers[publicKey] = config;
  } else if (operation === "replace") {
    if (!currentConfig.peers[publicKey]) throw new Error("Peer not found");
    currentConfig.peers[publicKey] = config;
  }
  return addDevice(interfaceName, currentConfig);
}