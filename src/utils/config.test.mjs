import fs from "node:fs";
import path from "node:path";
import __config from "./config.js";
import __keygen from "./keygen.js";
const { createConfig, parseConfig } = __config, { keygen } = __keygen;

describe("Parse and Create config", function() {
  it("Create server config", async () => {
    const interfaceKeys = await keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
  it("Create client config", async () => {
    const interfaceKeys = await keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
});