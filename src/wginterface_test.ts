import test from "node:test";
import { Wireguard, getConfig, setConfig } from "./wginterface.js";
import { presharedKey, privateKey, publicKey } from "./key.js";
import assert from "node:assert";

await test("Wireguard interface", async t => {
  const config = new Wireguard;
  config.name = "wg23";
  if (process.platform === "darwin") config.name = "utun23";

  config.setPrivateKey(await privateKey());
  config.addNewAddress("10.66.66.1/32");
  config.addNewAddress("fd42:42:42::1/128");

  const peer1 = await privateKey();
  config.addNewPeer(publicKey(peer1), {
    keepInterval: 15,
    presharedKey: await presharedKey(),
    allowedIPs: [
      "10.66.66.2/32"
    ]
  });

  const peer2 = await privateKey();
  config.addNewPeer(publicKey(peer2), {
    keepInterval: 0,
    allowedIPs: [
      "10.66.66.3/32"
    ]
  });

  const jsonConfig = config.toJSON();

  let skip: string;
  await t.test("Create and Set config in interface", async () => setConfig(jsonConfig).catch(err => { skip = "Cannot set wireguard config"; return Promise.reject(err); }));
  await t.test("Get config from interface", { skip }, async () => {
    const config = await getConfig(jsonConfig.name);
    // console.dir(config, { depth: null });

    if (!config.peers[publicKey(peer1)]) throw new Error("Peer not exists in interface");
    if (!config.peers[publicKey(peer2)]) throw new Error("Peer not exists in interface");

    assert.equal(config.peers[publicKey(peer1)].keepInterval, jsonConfig.peers[publicKey(peer1)].keepInterval);
    assert.equal(config.peers[publicKey(peer1)].presharedKey, jsonConfig.peers[publicKey(peer1)].presharedKey);

    assert.deepEqual(config.peers[publicKey(peer1)].allowedIPs, jsonConfig.peers[publicKey(peer1)].allowedIPs);
    assert.deepEqual(config.peers[publicKey(peer2)].allowedIPs, jsonConfig.peers[publicKey(peer2)].allowedIPs);
  });

  await t.test("Delete interface if exists", { skip }, async () => config.delete());
});