import * as netlink from "netlink";

export async function getFamily() {
  const generic = netlink.createGenericNetlink();
  const Family = await generic.ctrlRequest(netlink.genl.Commands.GET_FAMILY, {familyName: "wireguard"}, { flags: netlink.FlagsGet.DUMP });
  if (Family.length === 0) throw new Error("No wireguard family found");
  return Family[0].familyId;
}

export type deviceList = {name: string, index: number};
export async function getDevices(): Promise<deviceList[]> {
  const rt = netlink.createRtNetlink();
  const Devices = await rt.getLinks();
  console.log("%o", Devices.map(d => d.attrs.linkinfo?.toString()));
  return Devices.map(d => ({name: d.attrs.ifname, index: d.data.index}));
}
getDevices();

export async function createInterface(name: string) {
  const rt = netlink.createRtNetlink();
  rt.newLink({
    type: "NONE",
    family: await getFamily(),
    flags: {
      lowerUp: true,
      noarp: true,
      running: true,
      up: true
    }
  })
}