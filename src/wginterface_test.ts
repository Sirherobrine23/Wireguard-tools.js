import test from "node:test";
import { setConfig, deleteInterface, WgConfigSet, getConfig } from "./wginterface.js";
import { publicKey } from "./key.js";
import { userInfo } from "os";

if (process.platform === "win32" || process.platform === "linux" && (userInfo().uid === 0)) {
  test("Wireguard configuration", async t => {
    // Config base
    const peer1Key = 'EKgSatFzZtsv1qFJ6gE8HqfuA+tXzW+7vDeVc7Xaa2E=', peer2Key = '4BSvgiM9j5jjuR0Vg3gbqTFD5+CyuOU2K2kJE5+cakQ=',
    config: WgConfigSet = {
      privateKey: "4GTKsUfzodunTXaHtY/u+JhQN1D2CP1Sc+4D1VmpylY=",
      address: [
        "10.66.124.1/32"
      ],
      peers: {}
    };

    config.peers[publicKey(peer1Key)] = {
      allowedIPs: [
        "10.66.124.2"
      ]
    }

    await t.test("Set config in interface", async () => {
      await setConfig("wg23", config);
    });

    await t.test("Get config in interface", async () => {
      const __config = await getConfig("wg23");
      if (!__config.peers[publicKey(peer1Key)]) throw new Error("Not exist peer 1!");
    });

    config.peers[publicKey(peer1Key)].removeMe = true;
    config.peers[publicKey(peer2Key)] = {
      allowedIPs: [
        "10.66.124.3"
      ]
    }

    await t.test("Set config in interface", async () => {
      await setConfig("wg23", config);
    });

    await t.test("Get config in interface", async () => {
      const __config = await getConfig("wg23");
      if (__config.peers[publicKey(peer1Key)]) throw new Error("Invalid config get!");
      if (!__config.peers[publicKey(peer2Key)]) throw new Error("Not exist peer 2!");
    });

    await t.test("Delete interface", async () => {
      await deleteInterface("wg23");
    });
  });
}