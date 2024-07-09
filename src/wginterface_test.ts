import assert from "node:assert";
import test from "node:test";
import { format } from "node:util";
import { presharedKey, privateKey, publicKey } from "./key.js";
import { Config, deleteInterface, getConfig, setConfig } from "./wginterface.js";

await test("Wireguard interface", async t => {
  const newConfig: Config = {
    name: process.platform === "darwin" ? "utun23" : "wg10",
    privateKey: await privateKey(),
    portListen: 8260,
    address: [
      "10.66.66.1/24"
    ],
    peers: {}
  }
  for (let i = 0; i != 10; i++) {
    newConfig.peers[publicKey(await privateKey())] = {
      presharedKey: await presharedKey(),
      keepInterval: 25,
      allowedIPs: [
        format("10.66.66.%d/32", i+2)
      ],
    }
  }

  function checkExists<T extends any[]>(arg0: T, arg1: T) {
    for (const a1 of arg0) {
      if (!Array.from(arg1).includes(a1)) throw new Error(format("%O not includes in %O", a1, arg1))
    }
  }

  await t.test("Set config", async () => setConfig(newConfig));
  await t.test("Get config and check", async () => {
    const currentConfig = await getConfig(newConfig.name)
    assert.equal(currentConfig.privateKey, newConfig.privateKey)
    for (const pubKey in newConfig.peers) {
      if (!currentConfig.peers[pubKey]) throw new Error("one peer not exists in currentConfig")
      else if (currentConfig.peers[pubKey].presharedKey != newConfig.peers[pubKey].presharedKey) throw new Error("presharedKey is mismatch");
      else if (currentConfig.peers[pubKey].keepInterval != newConfig.peers[pubKey].keepInterval) throw new Error("keepInterval is mismatch");
      checkExists(newConfig.peers[pubKey].allowedIPs, currentConfig.peers[pubKey].allowedIPs);
    }
  });
  await t.test("Deleting interface", async () => deleteInterface(newConfig.name));
});
