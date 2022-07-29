import { addDevice, delDevice, getAllPeersAndInterface } from "./bridge";
import { keygen as keyGen } from "./utils/keygen";

export default async function main() {
  if (getAllPeersAndInterface()["wg_test"]) {
    delDevice("wg_test");
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  const Keys = await keyGen(false);
  console.log("Add device:", await addDevice({
    name: "wg_test",
    portListen: 51880,
    privateKey: Keys.private,
    publicKey: Keys.public
  }));
  console.log("Del device:", delDevice("wg_test"));
  console.log("Get devices:", getAllPeersAndInterface());
}