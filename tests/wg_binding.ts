import { expect } from "chai";
import * as Bridge from "../src/wg_binding";
import * as utils from "../src/utils/index";
import { writeFileSync } from "fs";
const interfaceName = "sh23Test1235555";

describe("Create interface", async () => {
  it(`Create interface ('${interfaceName}')`, async () => {
    const serverKeys = await utils.keygen(false);
    // Make base config
    const deviceConfig: Bridge.wireguardInterface = {
      portListen: 51880,
      privateKey: serverKeys.private,
      Address: [],
      peers: {}
    };
    for (let i = 0; i < 3; i++) {
      const peerKey = await utils.keygen(true);
      const ips = [
        utils.nodeCidr4.randomIp("192.168.15.1/24"),
        utils.nodeCidr4.randomIp("192.168.15.1/24")
      ];
      deviceConfig.peers[peerKey.public] = {
        allowedIPs: [...ips, ...ips.map(utils.nodeCidr6.FourToSix)],
      };
      if (i%2 === 0) {
        deviceConfig.peers[peerKey.public].endpoint = utils.nodeCidr4.randomIp("20.0.0.1/24")+":51880";
        deviceConfig.peers[peerKey.public].presharedKey = peerKey.preshared;
      }
      ips.map(utils.nodeCidr4.fistIp).forEach(ip => {if (deviceConfig.Address) {if (!deviceConfig.Address.find(ips => ip === ips)) deviceConfig.Address.push(ip);}});
    }
    // remove duplicates
    if (deviceConfig.Address) deviceConfig.Address.push(...deviceConfig.Address.map(utils.nodeCidr6.FourToSix));
    // console.log("New device config: '%o'", deviceConfig);
    return Bridge.addDevice(interfaceName, deviceConfig);
  });
  it("Convert wireguardInterface to config utils", () => {
    const wireguardInterface = Bridge.showAll()[interfaceName];
    const config = utils.config.Convert_wireguardInterface_to_config_utils(wireguardInterface);
    return expect(config.interface.private).equal(wireguardInterface.privateKey);
  });
  after(async () => {
    const deviceConfig = Bridge.showAll()[interfaceName];
    if (!!deviceConfig) {
      describe("Cleaning test interface", ()=>{
        it(`Remove interface ${interfaceName}`, () => Bridge.delDevice(interfaceName));
      });
      writeFileSync(`${__dirname}/../${interfaceName}.addrs.json`, JSON.stringify(deviceConfig, null, 2));
    }
  });
});