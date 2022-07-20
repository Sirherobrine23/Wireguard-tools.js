import * as wireguardNetlink from "./index";

export default async function main() {
  const getDevices = await wireguardNetlink.getDevices();
}