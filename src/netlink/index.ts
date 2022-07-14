import * as netlink from "netlink";

// Defines from uapi/wireguard.h
const WG_GENL_NAME = "wireguard"
const WG_GENL_VERSION = 1
export const WG_KEY_LEN = 32

// WireGuard Device commands
export const WG_CMD_GET_DEVICE = 0
export const WG_CMD_SET_DEVICE = 1

// Wireguard Device attributes
export const WGDEVICE_A_UNSPEC = 0
export const WGDEVICE_A_IFINDEX = 1
export const WGDEVICE_A_IFNAME = 2
export const WGDEVICE_A_PRIVATE_KEY = 3
export const WGDEVICE_A_PUBLIC_KEY = 4
export const WGDEVICE_A_FLAGS = 5
export const WGDEVICE_A_LISTEN_PORT = 6
export const WGDEVICE_A_FWMARK = 7
export const WGDEVICE_A_PEERS = 8

// WireGuard Device flags
export const WGDEVICE_F_REPLACE_PEERS = 1

// WireGuard Allowed IP attributes
export const WGALLOWEDIP_A_UNSPEC = 0
export const WGALLOWEDIP_A_FAMILY = 1
export const WGALLOWEDIP_A_IPADDR = 2
export const WGALLOWEDIP_A_CIDR_MASK = 3

// WireGuard Peer flags
export const WGPEER_F_REMOVE_ME = 0
export const WGPEER_F_REPLACE_ALLOWEDIPS = 1
export const WGPEER_F_UPDATE_ONLY = 2

// Specific defines
export const WG_MAX_PEERS = 1000
export const WG_MAX_ALLOWEDIPS = 1000

export async function getFamily() {
  const generic = netlink.createGenericNetlink();
  const Family = await generic.ctrlRequest(netlink.genl.Commands.GET_FAMILY, {familyName: WG_GENL_NAME}, { flags: netlink.FlagsGet.DUMP });
  if (Family.length === 0) throw new Error("No wireguard family found");
  return Family[0].familyId;
}

export type deviceList = {name: string, index: number};
export async function getDevices() {
  const rt = netlink.createRtNetlink();
  const generic = netlink.createGenericNetlink();
  const devices: deviceList[] = []
  for (const link of await rt.getLinks()) {
    const interfaceName = link.attrs.ifname||link.attrs.altIfname||link.attrs.ifalias||"Null", interfaceIndex = link.data.index;
    await generic.request(await getFamily(), WG_CMD_GET_DEVICE, WG_GENL_VERSION, Buffer.from("Null")).then(([res, info]) => {
      console.log(res, info);
      if (res.length === 0) throw new Error("Not wireguard")
      devices.push({
        index: interfaceIndex,
        name: interfaceName
      });
    }).catch((err: Error) => {
      console.log(interfaceName, err.toString());
      return err;
    });
  }

  return devices;
}
getDevices().then(console.log)