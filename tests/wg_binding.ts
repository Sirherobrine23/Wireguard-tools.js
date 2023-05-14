import { writeFileSync } from "fs";
import { expect } from "chai";
import * as Bridge from "../src/wg_binding";
import * as utils from "../src/utils/index";
const interfaceName = "sh23Test1235555";

// Make base config
const deviceConfig: Bridge.wireguardInterface = {
  portListen: Math.floor(Math.random() * (65535 - 1024) + 1024),
  privateKey: utils.genPrivateKey(),
  replacePeers: true,
  Address: [],
  peers: {}
};

// Create Random Peer
for (let i = 0; i < 20; i++) {
  const peerKey = utils.keygen(true);
  const ips = [utils.nodeCidr4.randomIp(Math.random() > 0.5 ? "192.168.15.1/24" : "10.0.0.1/8"), utils.nodeCidr4.randomIp(Math.random() > 0.5 ? "10.0.0.1/8" : "192.168.15.1/24")];
  deviceConfig.peers[peerKey.public] = {
    allowedIPs: [...ips, ...ips.map(utils.nodeCidr6.FourToSix)],
    removeMe: Math.random() > 0.7,
  };
  if (i%2 === 0) deviceConfig.peers[peerKey.public].presharedKey = peerKey.preshared;
  ips.map(utils.nodeCidr4.fistIp).forEach(ip => {if (deviceConfig.Address) {if (!deviceConfig.Address.find(ips => ip === ips)) deviceConfig.Address.push(ip);}});
}

// Add IPv6 addresses
if (deviceConfig.Address) deviceConfig.Address.push(...deviceConfig.Address.map(utils.nodeCidr6.FourToSix));

describe("Wireguard interface", () => {
  it("Pretty wireguard interface config", () => {
    const config = utils.config.prettyConfig(deviceConfig);
    return expect(config.interface.private).equal(deviceConfig.privateKey);
  });
  if (process.platform === "linux") {
    it("Maneger", () => {
      Bridge.addDevice(interfaceName, deviceConfig);
      if (!(Bridge.listDevices().includes(interfaceName))) throw new Error("Invalid list devices");
      const raw = Bridge.parseWgDevice(interfaceName);
      writeFileSync(`${__dirname}/../${interfaceName}.addrs.json`, JSON.stringify({
        deviceConfig,
        raw,
        get: utils.config.prettyConfig(raw)
      }, null, 2));
      Bridge.removeInterface(interfaceName);
    });
  }
});
