const wg = require("./src/index.ts");

describe("Keys", function() {
  it("Preshared key", async () => wg.key.presharedKey());
  it("Private key", async () => wg.key.privateKey());
  it("Public key", async () => wg.key.publicKey(await wg.key.privateKey()));
  it("Key pack 1", async () => wg.key.genKey());
  it("Key pack 2", async () => wg.key.genKey(true));
});

const interfaceName = String(((process.env.WG_INETRFACE||"").length > 0) ? process.env.WG_INETRFACE : (process.platform === "darwin" ? ("utun").concat(String(randomInt(20, 1023))) : "wgtest"));

describe(("Wireguard interface (").concat(interfaceName, ")"), function() {
  this.timeout(Infinity);
  /** @type { wg.WgConfig } */
  const interfaceConfig = {};
  it("Generate config", async () => {
    interfaceConfig.Address = [ "10.0.0.1/24" ];
    interfaceConfig.privateKey = await wg.key.privateKey();
    interfaceConfig.portListen = 8030;
    interfaceConfig.peers = {};
    await Promise.all(Array(10).fill(null).map(async (_, peerGenIndex) => {
      const peerKey = await wg.key.genKey(true);
      interfaceConfig.peers[peerKey.publicKey] = {
        presharedKey: peerKey.presharedKey,
        allowedIPs: [ `10.0.0.${peerGenIndex+2}/24` ],
        keepInterval: 5
      };
    }));
    // console.dir(interfaceConfig, { depth: null });
  });
  it("Set config", async () => wg.setConfig(interfaceName, interfaceConfig));
  it("Get config", async () => wg.getConfig(interfaceName));
  it("Delete interface", async () => wg.deleteInterface(interfaceName));
});