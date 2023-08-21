const { format } = require("node:util");
const fs = require("node:fs");
const utils = require("../src/utils/index");
const { randomInt } = require("node:crypto");
const randomGen = randomInt(5000, 9999);
const wg0 = fs.readFileSync(__dirname+"/../configsExamples/wg0.ini", "utf8"); // Server config
const wg1 = fs.readFileSync(__dirname+"/../configsExamples/wg1.ini", "utf8"); // Client config

// Key Generation
describe("Key Gen", () => {
  it("Without Preshared key", () => {
    const withOut = utils.keygen();
    if (!withOut["preshared"]) return;
    throw new Error("Keygen failed");
  });
  it("with Preshared key", () => {
    const withPre = utils.keygen(true);
    if (withPre["preshared"]) return;
    throw new Error("Keygen failed");
  });
  it(format("Generate %f pre-shared keys", randomGen), () => {
    const keyMap = new Set();
    for (let i = 0; i < randomGen; i++) {
      const key = utils.genPresharedKey();
      if (keyMap.has(key)) throw new Error(format("Keygen failed, generate %f at time", keyMap.size));
      keyMap.add(key);
    }
  });
  it(format("Generate %f private keys", randomGen), () => {
    const keyMap = new Set();
    for (let i = 0; i < randomGen; i++) {
      const key = utils.genPrivateKey();
      if (keyMap.has(key)) throw new Error(format("Keygen failed, generate %f at time", keyMap.size));
      keyMap.add(key);
    }
  });
});

// Shuffle IP and Convert to IPv6
describe("Random IP and IPv4 in to IPv6", () => {
  it("Shuffle IP", () => {
    const Ip = utils.nodeCidr4.randomIp("10.0.0.0/24");
    if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(Ip)) return;
    throw new Error("Shuffle IP failed");
  });
  it("IPv6 Convert", () => {
    const Ip = utils.nodeCidr4.randomIp("192.168.1.1/24");
    const IPv6 = utils.nodeCidr6.FourToSix(Ip);
    if (!/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(IPv6)) return;
    throw new Error("IPv6 conversion failed");
  });
});

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