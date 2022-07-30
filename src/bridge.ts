// @ts-ignore
import Bridge from "../wireguard_bridge";

export type wireguardInterface = {
  publicKey: string,
  privateKey: string,
  portListen: number,
  peers: {
    [peerPublicKey: string]: {
      presharedKey?: string,
      endpoint: string,
      rxBytes?: number,
      txBytes?: number,
      keepInterval?: number,
      lastHandshake?: Date,
    }
  }
};
export type PeerAndInterface = {[interfaceName: string]: wireguardInterface};

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
export function showAll(): PeerAndInterface {return Bridge.getPeers();}

/**
 * Get one Wireguard Interface with its Peers
 *
*/
export function show(wgName: string): wireguardInterface {
  const insterfaces = showAll();
  if (!insterfaces[wgName]) throw new Error(`Wireguard interface ${wgName} not found`);
  return insterfaces[wgName];
}

/**
 * Get only interfaces names
 */
export function getDeviceName() {return Object.keys(showAll());}

export type newDevice = {
  name: string,
  portListen: number
  publicKey: string,
  privateKey: string
};

export function addDevice(interfaceConfig: newDevice): wireguardInterface {
  const { name: interfacename, portListen, publicKey, privateKey  } = interfaceConfig;
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  if (showAll()[interfacename]) throw new Error("interface name is already in use");
  const res = Bridge.addNewDevice(interfacename, portListen, publicKey, privateKey);
  if (res === -1) throw new Error("Unable to add device");
  else if (res === -2) throw new Error("Unable to set device");
  return showAll()[interfacename];
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