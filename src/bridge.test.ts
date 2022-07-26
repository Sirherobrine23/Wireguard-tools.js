import * as bridge from "./bridge";

export default async function main() {
  if (bridge.getDevices().some(x => x === "wg_test")) bridge.delDevice("wg_test")
  console.log("Get devices:", bridge.getDevices());
  console.log("Add device:", await bridge.addDevice("wg_test"));
  console.log("Get devices:", bridge.getDevices());
  console.log("Del device:", bridge.delDevice("wg_test"));
  console.log("Get devices:", bridge.getDevices());
}