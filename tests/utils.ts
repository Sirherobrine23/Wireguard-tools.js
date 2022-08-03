import * as fs from "node:fs";
import * as utils from "../src/utils/index";

// Server config
const wg0 = fs.readFileSync(__dirname+"/../configsExamples/wg0.ini", "utf8");
// Client config
const wg1 = fs.readFileSync(__dirname+"/../configsExamples/wg1.ini", "utf8");

// Key Generation
describe("Key Gen", () => {
  it("Without Preshared key", async () => {
    const withOut = await utils.keygen();
    if (!withOut["preshared"]) return;
    throw new Error("Keygen failed");
  });
  it("with Preshared key", async () => {
    const withPre = await utils.keygen(true);
    if (withPre["preshared"]) return;
    throw new Error("Keygen failed");
  });
});

// Parse Wireguard Config
describe("Parse config", () => {
  it("Server", () => {
    const severObject = utils.config.parseConfig(wg0) as {type: "server", data: utils.config.serverConfig};
    if (severObject.type === "server") return;
    throw new Error("Config parse failed");
  });
  it("Client", () => {
    const clientObject = utils.config.parseConfig(wg1) as {type: "client", data: utils.config.clientConfig};
    if (clientObject.type === "client") return;
    throw new Error("Config parse failed");
  });
});

// Shuffle IP and Convert to IPv6
describe("Random IP and IPv4 in to IPv6", () => {
  it("Shuffle IP", () => {
    const Ip = utils.ipManeger.shuffleIp("10.0.0.0/24");
    if (/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(Ip)) return;
    throw new Error("Shuffle IP failed");
  });
  it("IPv6 Convert", () => {
    const Ip = utils.ipManeger.shuffleIp("192.168.1.1/24");
    const IPv6 = utils.ipManeger.convertToIpv6(Ip);
    if (!/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(IPv6)) return;
    throw new Error("IPv6 conversion failed");
  });
});