import { listDevices, parseWgDevice, addDevice, wgConfig, utils } from "wireguard-tools.js";
const deviceName = (await listDevices()).at(-1);
if (!deviceName) {
  console.info("Create wireguard interface");
  process.exit(-1);
}

// Get current config
const currentConfig = new wgConfig(await parseWgDevice(deviceName));

// Create Peer
const peer = await currentConfig.newPeer(true);
console.log("Add %O peer", peer.publicKey);

// Set to interface
await addDevice(deviceName, currentConfig);
console.dir(currentConfig, { depth: null });