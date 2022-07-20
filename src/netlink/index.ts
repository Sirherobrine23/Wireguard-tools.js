import * as netlink from "netlink";
import * as childPromises from "../lib/childPromise";
import * as wgDefines from "./defines";
export type { deviceList } from "./defines";

// export async function getFamily() {
//   const generic = netlink.createGenericNetlink();
//   const Family = await generic.ctrlRequest(netlink.genl.Commands.GET_FAMILY, {familyName: wgDefines.WG_GENL_NAME}, { flags: netlink.FlagsGet.DUMP });
//   if (Family.length === 0) throw new Error("No wireguard family found");
//   return Family[0].familyId;
// }


/**
 * Get all wireguard interfaces and their global stats
*/
export async function getDevices(): Promise<wgDefines.deviceList[]> {
  const rt = netlink.createRtNetlink();
  const addrs = (await rt.getLinks()).filter(({attrs}) => /wireguard/.test(attrs?.linkinfo?.toString()))
  if (addrs.length === 0) throw new Error("No wireguard devices found");
  return addrs.map(({data: {index}, attrs: {ifname, altIfname, mtu, stats64: {rxBytes, txBytes}}}) => ({index, mtu, bytes: {rx: rxBytes, tx: txBytes}, name: ifname||altIfname}) as wgDefines.deviceList);
}

/**
 * Create interface and add ip addresses if iformation is provided
 *
 * This is an implementation using `ip` commands, so it has this compatibility, I will be converting with @mildsunrise to use `netlink`.
 */
export async function addInterface(options: {interfaceName: string, ip?: string[]}) {
  if (!options.interfaceName) throw new Error("Interface name is required");
  const interfaceName = options.interfaceName;
  await childPromises.execFile("ip", ["link", "add", interfaceName, "type", "wireguard"]);
  if (!!options.ip) {
    options.ip = options.ip.filter(x => /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]{0,3}$/.test(x));
    if (options.ip.length > 0) await childPromises.execFile("ip", ["addr", "add", ...options.ip, "dev", interfaceName]);
  }
}

// export async function expirementalAddInterface(options: {interfaceName: string, ip?: string[]}) {
//   if (!options.interfaceName) throw new Error("Interface name is required");
//   const interfaceName = options.interfaceName;
//   if (!!options.ip) options.ip = options.ip.filter(x => /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]{0,3}$/.test(x));
//   const rt = netlink.createRtNetlink();
//   rt.newLink({
//     type: "NONE"
//   }, {
//     ifname: interfaceName,
//   })
// }