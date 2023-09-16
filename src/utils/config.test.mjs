import __config from "./config.js";
import __keygen from "./keygen.js";
const { createConfig } = __config, { keygen } = __keygen;

describe("Parse and Create config", function() {
  it("Create server config string", async () => {
    const interfaceKeys = await keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
  it("Create client config string", async () => {
    const interfaceKeys = await keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
  it("wgConfig", async () => {
    const interfaceKeys = await keygen();
    const config = new __config.wgConfig();
    config.Address = ["10.66.66.1/24"];
    config.replacePeers = true;
    config.privateKey = interfaceKeys.private;
    config.publicKey = interfaceKeys.public;
    let genKeys = 10;
    while (--genKeys > config.size) await config.newPeer(genKeys % 2 === 0);
    const peer = Array.from(config.keys())[0];
    config.getClientConfig(peer, "localhost");
    config.getServerConfig();
    config.toJSON();
    config.toString();
  });
});