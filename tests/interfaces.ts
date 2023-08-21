import { writeFileSync } from "fs";
import * as Bridge from "../src/mergeSets";
import * as utils from "../src/utils/index";
import { randomInt } from "crypto";

// Make base config
const interfaceName = String(((process.env.WG_INETRFACE||"").length > 0) ? process.env.WG_INETRFACE : (process.platform === "darwin" ? "utun" : "shtest").concat(String(randomInt(20, 1023))));
const deviceConfig: Bridge.wireguardInterface = {
  portListen: randomInt(1024, 65535),
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
    allowedIPs: ips.concat(ips.map(utils.nodeCidr6.FourToSix)),
    removeMe: Math.random() > 0.7,
  };
  if (i%2 === 0) deviceConfig.peers[peerKey.public].presharedKey = peerKey.preshared;
  ips.map(utils.nodeCidr4.fistIp).forEach(ip => {if (deviceConfig.Address) {if (!deviceConfig.Address.find(ips => ip === ips)) deviceConfig.Address.push(ip);}});
}

// Add IPv6 addresses
if (deviceConfig.Address) deviceConfig.Address.push(...deviceConfig.Address.map(utils.nodeCidr6.FourToSix));

describe("Wireguard interface", () => {
  it("Fist list", () => Bridge.listDevices());
  it("Maneger", async () => {
    await Bridge.addDevice(interfaceName, deviceConfig);
    if (!((await Bridge.listDevices()).includes(interfaceName))) throw new Error("Invalid list devices");
  });

  it("Get config", async () => {
    const raw = await Bridge.parseWgDevice(interfaceName);
    writeFileSync(`${__dirname}/../${interfaceName}.addrs.json`, JSON.stringify({
      deviceConfig,
      raw
    }, null, 2));
  });

  it("After list", async () => await Bridge.listDevices());
});
