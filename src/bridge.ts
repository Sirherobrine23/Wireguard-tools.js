// @ts-ignore
import Bridge from "../build/Release/wireguard_bridge";

export type wireguardInterface = {
  publicKey: string,
  privateKey: string,
  peers: {
    [peerPublicKey: string]: {
      presharedKey?: string,
      rxBytes?: number,
      txBytes?: number,
      keepInterval?: number,
      lastHandshake?: Date,
    }
  }
};
export type PeerAndInterface = {[interfaceName: string]: wireguardInterface};
export function getAllPeersAndInterface(): PeerAndInterface {  return Bridge.getPeers();}
export function getDevices() {return Object.keys(getAllPeersAndInterface);}

export type newDevice = {
  name: string,
  portListen: number
  publicKey: string,
  privateKey: string
};
export async function addDevice(interfaceConfig: newDevice): Promise<wireguardInterface> {
  const { name: interfacename, portListen, publicKey, privateKey  } = interfaceConfig;
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  if (getAllPeersAndInterface()[interfacename]) throw new Error("interface name is already in use");
  const res = Bridge.addDevice(interfacename, portListen, publicKey, privateKey);
  if (res === -1) throw new Error("Unable to add device");
  else if (res === -2) throw new Error("Unable to set device");
  await new Promise(resolve => setTimeout(resolve, 1000));
  return getAllPeersAndInterface()[interfacename];
}

export function delDevice(interfacename: string) {
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  if (!getAllPeersAndInterface()[interfacename]) throw new Error("interface name is not in use");
  const res = Bridge.delDevice(interfacename);
  if (res === 0) return;
  throw new Error("Deleteinterface failed, return code: " + res);
}