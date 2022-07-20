// Defines from uapi/wireguard.h
export const WG_GENL_NAME = "wireguard"
export const WG_GENL_VERSION = 1
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

// Export type for wireguard device
export type deviceList = {name: string, index: number, mtu: number, bytes: {rx: bigint, tx: bigint}};