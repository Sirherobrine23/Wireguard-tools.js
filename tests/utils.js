import * as fs from "node:fs";
import * as utils from "../src/utils/index";

// Server config
const wg0 = fs.readFileSync(__dirname+"/../configsExamples/wg0.ini", "utf8");
// Client config
const wg1 = fs.readFileSync(__dirname+"/../configsExamples/wg1.ini", "utf8");

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