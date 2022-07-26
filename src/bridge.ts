// @ts-ignore
import Bridge from "../build/Release/wireguard_bridge";
Bridge.getPeers()
export function getDevices() {
  const devices = Bridge.getDeviceNames() as {[key: string]: string};
  return Object.keys(devices).filter(x => !x.trim());
}

export async function addDevice(interfacename: string) {
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  console.log(getDevices().some(x => interfacename === x), getDevices())
  if (getDevices().some(x => interfacename === x)) throw new Error("interface name is already in use");
  const res = Bridge.addDevice(interfacename);
  console.log("Add:", res)
  if (res < 0) {
    let count = 0;
    while (true) {
      if (count++ > 15) return;
      const devices = getDevices();
      if (devices.some(x => interfacename === x)) return;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  throw new Error("interface name is already in use");
}

export function delDevice(interfacename: string) {
  if (!interfacename) throw new Error("interface name is required");
  if (interfacename.length > 16) throw new Error("interface name is too long");
  if (!/^[a-zA-Z0-9_]+$/.test(interfacename)) throw new Error("interface name is invalid");
  if (!getDevices().some(x => interfacename === x)) throw new Error("interface name is not in use");
  const res = Bridge.delDevice(interfacename);
  console.log("Delete:", res)
  if (res < 0) return;
  throw new Error("interface name is not found");
}