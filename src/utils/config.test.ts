import fs from "node:fs";
import path from "node:path";
import { createConfig, parseConfig } from "./config";
import { keygenAsync } from "./keygen";
const wg0 = fs.readFileSync(path.resolve(__dirname, "../../configsExamples/wg0.ini"), "utf8"); // Server config
const wg1 = fs.readFileSync(path.resolve(__dirname, "../../configsExamples/wg1.ini"), "utf8"); // Client config

describe("Parse and Create config", function() {
  it("Parse server config", () => parseConfig(wg0));
  it("Parse client config", () => parseConfig(wg1));
  it("Create server config", async () => {
    const interfaceKeys = await keygenAsync();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
  it("Create client config", async () => {
    const interfaceKeys = await keygenAsync();
    const config = {
      publicKey: interfaceKeys.public,
      privateKey: interfaceKeys.private,
      portListen: 31809,
      peers: {}
    };
    createConfig(config);
  });
});