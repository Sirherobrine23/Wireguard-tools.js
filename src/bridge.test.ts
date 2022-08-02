import { utils } from "./index";
import * as Bridge from "./bridge";
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
  const serverKeys = await utils.keygen(false);
  const peerKeys = await utils.keygen(true);
  const peerKeys2 = await utils.keygen(true);
  const addtest = Bridge.addDevice({
    name: wireguardInterfaceName,
    portListen: 51880,
    privateKey: serverKeys.private,
    peers: {
      [peerKeys.public]: {
        keepInterval: 25,
        presharedKey: peerKeys.preshared,
        allowedIPs: [
          utils.ipManeger.shuffleIp("10.0.0.1/24"),
          utils.ipManeger.shuffleIp("10.0.0.1/24"),
        ]
      },
      [peerKeys2.public]: {
        presharedKey: peerKeys2.preshared,
        allowedIPs: [
          utils.ipManeger.shuffleIp("192.168.15.1/24"),
          utils.ipManeger.shuffleIp("192.168.15.1/24"),
        ]
      }
    }
  });
  console.log("Sucess to add "+wireguardInterfaceName);
  const secondGet = Bridge.showAll();
  // Bridge.delDevice(wireguardInterfaceName)
  // console.log("Sucess to delete wg_test");
  return {
    addtest,
    gets: {
      fist: fistGet,
      second: secondGet
    }
  };
}