import { networkInterfaces } from "node:os";
import { expect } from "chai";
import * as Bridge from "../src/bridge";
import * as utils from "../src/utils/index";
const interfaceName = !networkInterfaces()["wg_test"] ? "sh23Test":"wg_test";

// Show
describe("Show", () => {
  it("All", () => {
    Bridge.showAll();
  });
});

describe("Create interface", () => {
  it(`Create interface ('${interfaceName}')`, async () => {
    const serverKeys = await utils.keygen(false);
    // Make base config
    const deviceConfig: Bridge.wireguardInterface & {name: string} = {
      name: interfaceName,
      portListen: 51880,
      privateKey: serverKeys.private,
      Address: [
        utils.nodeCidr4.randomIp("10.0.0.1/24"),
        utils.nodeCidr4.randomIp("10.0.0.1/24"),
        utils.nodeCidr4.randomIp("10.0.0.1/24"),
        utils.nodeCidr4.randomIp("10.0.0.1/24"),
      ],
      peers: {}
    };
    for (let i = 0; i < 10; i++) {
      const peerKey = await utils.keygen(true);
      deviceConfig.peers[peerKey.public] = {
        allowedIPs: [
          utils.nodeCidr4.randomIp("192.168.15.1/24"),
          utils.nodeCidr6.FourToSix(utils.nodeCidr4.randomIp("192.168.15.1/24")),
          utils.nodeCidr4.randomIp("192.168.15.1/24"),
          utils.nodeCidr6.FourToSix(utils.nodeCidr4.randomIp("192.168.15.1/24")),
        ]
      };
      if (i%2 === 0) {
        deviceConfig.peers[peerKey.public].endpoint = utils.nodeCidr4.randomIp("20.0.0.1/24")+":51880";
        deviceConfig.peers[peerKey.public].presharedKey = peerKey.preshared;
      }
    }
    Bridge.addDevice(deviceConfig);
  });
  it("Convert wireguardInterface to config utils", () => {
    const wireguardInterface = Bridge.showAll()[interfaceName];
    const config = utils.config.Convert_wireguardInterface_to_config_utils(wireguardInterface);
    return expect(config.interface.private).equal(wireguardInterface.privateKey);
  });
  after(async () => {
    describe("Cleaning", ()=>{
      it(`Remove interface ${interfaceName}`, () => {
        // Bridge.delDevice(interfaceName);
      });
    });
  });
});
