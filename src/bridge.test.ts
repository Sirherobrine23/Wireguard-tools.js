import { addDevice, delDevice, getAllPeersAndInterface } from "./bridge";
import keyGen from "./utils/keygen";

export default async function main() {
  if (getAllPeersAndInterface()["wg_test"]) {
    delDevice("wg_test");
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  console.log("Get devices:\n%o\n", getAllPeersAndInterface());
  const Keys = await keyGen(false);
  console.log("Add device:", await addDevice({
    name: "wg_test",
    portListen: 51880,
    privateKey: Keys.private,
    publicKey: Keys.public
  }));
  console.log("Get devices:", getAllPeersAndInterface());
  console.log("Del device:", delDevice("wg_test"));
  console.log("Get devices:", getAllPeersAndInterface());
}