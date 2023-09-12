import { listDevices, getConfig, setConfig, utils } from "../../src/index.mjs";
const deviceName = (await listDevices()).at(-1);
if (!deviceName) {
  console.info("Create wireguard interface");
  process.exit(-1);
}

// Get current config
const currentConfig = new utils.wgConfig(await getConfig(deviceName.name));
if (!currentConfig.privateKey) currentConfig.privateKey = await utils.genPrivate();
if (!(currentConfig.Address||[]).length) currentConfig.Address = [ "10.66.66.1/24" ];
if (!(currentConfig.DNS||[]).length) currentConfig.DNS = [ "1.1.1.1", "8.8.8.8" ];
currentConfig.replacePeers = true;

// Create Peer
const peer = await currentConfig.newPeer(true);
console.log("Add %O peer", peer.publicKey);

// Set to interface
await setConfig(deviceName.name, currentConfig.toJSON());
console.dir(currentConfig.toJSON(), { depth: null });