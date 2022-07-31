import * as Bridge from "./bridge";
import { keygen as keyGen } from "./utils/keygen";
const wireguardInterfaceName = "wg_test";

export function pre() {
  if (Bridge.showAll()[wireguardInterfaceName]) {
    console.log("Deleting wg_test");
    Bridge.delDevice(wireguardInterfaceName);
  }
}

export async function main() {
  const fistGet = Bridge.showAll();
  console.log("Sucess to get all interfaces");
  const Keys = await keyGen(false);
  const addtest = Bridge.addDevice({
    name: wireguardInterfaceName,
    portListen: 51880,
    privateKey: Keys.private,
    peers: {}
  });
  console.log("Sucess to add "+wireguardInterfaceName);
  const secondGet = Bridge.showAll();
  Bridge.delDevice(wireguardInterfaceName)
  console.log("Sucess to delete wg_test");
  return {
    addtest,
    gets: {
      fist: fistGet,
      second: secondGet
    }
  };
}