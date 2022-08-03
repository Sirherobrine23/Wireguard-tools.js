import * as Bridge from "../src/bridge";
import * as utils from "../src/utils/index";

// Show
describe("Show", () => {
  it("All", () => {
    Bridge.showAll();
  });
});


describe("Create interface", () => {
  it("Create interface", async () => {
    const serverKeys = await utils.keygen(false);
    const peerKeys = await utils.keygen(true);
    const peerKeys2 = await utils.keygen(true);
    if (Bridge.showAll()["wg_test"]) Bridge.delDevice("wg_test");
    Bridge.addDevice({
      name: "wg_test",
      portListen: 51880,
      privateKey: serverKeys.private,
      peers: {
        [peerKeys.public]: {
          keepInterval: 25,
          presharedKey: peerKeys.preshared,
          allowedIPs: [
            utils.ipManeger.shuffleIp("10.0.0.1/24"),
            utils.ipManeger.shuffleIp("10.0.0.1/24"),
            utils.ipManeger.convertToIpv6(utils.ipManeger.shuffleIp("10.0.0.1/24")),
            utils.ipManeger.convertToIpv6(utils.ipManeger.shuffleIp("10.0.0.1/24")),
          ]
        },
        [peerKeys2.public]: {
          presharedKey: peerKeys2.preshared,
          allowedIPs: [
            utils.ipManeger.shuffleIp("192.168.15.1/24"),
            utils.ipManeger.shuffleIp("192.168.15.1/24"),
            utils.ipManeger.convertToIpv6(utils.ipManeger.shuffleIp("192.168.15.1/24")),
            utils.ipManeger.convertToIpv6(utils.ipManeger.shuffleIp("192.168.15.1/24")),
          ]
        }
      }
    });
  });
});
