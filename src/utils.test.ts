import fs from "node:fs";
import * as utils from "../src/utils/index";
const wg0 = fs.readFileSync(__dirname+"/../configsExamples/wg0.ini", "utf8"); // Server config
const wg1 = fs.readFileSync(__dirname+"/../configsExamples/wg1.ini", "utf8"); // Client config

describe("Parse and Create config", function() {
  it("Parse server config", () => {
    utils.config.parseConfig(wg0);
  });
  it("Parse client config", () => {
    utils.config.parseConfig(wg1);
  });
  it("Create server config", () => {
    const interfaceKeys = utils.keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    utils.config.createConfig(config);
  });
  it("Create client config", () => {
    const interfaceKeys = utils.keygen();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    utils.config.createConfig(config);
  });
});