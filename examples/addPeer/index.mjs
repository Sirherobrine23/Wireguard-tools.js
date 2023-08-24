import { listDevices, parseWgDevice, addDevice, utils } from "wireguard-tools.js";
const deviceName = (await listDevices()).at(-1);
if (!deviceName) {
  console.info("Create wireguard interface");
  process.exit(-1);
}

// Get current config
const currentConfig = await parseWgDevice(deviceName);

// Create Peer
const peerKey = await utils.keygenAsync(true);
currentConfig.peers[peerKey.public] = { presharedKey: peerKey.preshared, allowedIPs: [ utils.ipManipulation.randomIp("10.22.66.1/24", Object.keys(currentConfig.peers).map(k => currentConfig.peers[k].allowedIPs).flat(2).filter(Boolean)) ] };
currentConfig.peers[peerKey.public].allowedIPs.push(utils.ipManipulation.toV6(currentConfig.peers[peerKey.public].allowedIPs.at(0)));
console.log("Add %O peer", peerKey.public);

// Set to interface
await addDevice(deviceName, currentConfig);
console.dir(currentConfig, { colors: true, depth: null });