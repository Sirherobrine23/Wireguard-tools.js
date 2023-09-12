import { equal, match } from "assert";
import {
  cidrCommonCidr, previousCidr, nextCidr,
  randomIp, previousIp, nextIp, count,
  toV6, fromV6,
} from "./ipm.js";

describe("IP Manipulation", function() {
  // CIDR
  it("cidrCommonCidr", () => equal(cidrCommonCidr(["192.168.1.1/24", "192.168.1.2/24", "192.168.1.3/24"]), "192.168.1.0/24"));
  it("previousCidr", () => equal(previousCidr("192.168.1.1/24"), "192.168.0.1/24"));
  it("nextCidr", () => equal(nextCidr("192.168.1.1/24"), "192.168.2.1/24"));

  // IP
  it("randomIp", () => match(randomIp("192.168.0.0/24"), /^192\.168\.0\.[0-9]+$/));
  it("previousIp", () => equal(previousIp("192.168.0.0"), "192.167.255.255"));
  it("nextIp", () => equal(nextIp("192.168.0.0"), "192.168.0.1"));
  it("Count", () => equal(count("192.168.0.0/24"), 256));

  // Convert
  it("To IPv6", () => equal(toV6("192.178.66.255"), "0000:0000:0000:0000:0000:ffff:c0b2:42ff"));
  it("From IPv6", () => equal(fromV6("0000:0000:0000:0000:0000:ffff:c0b2:42ff"), "192.178.66.255"));

  it("From IPv6, compressedv6 false", () => equal(fromV6("0000:0000:0000:0000:0000:ffff:c0b2:42ff"), "192.178.66.255"));
  it("To IPv6, compressedv6 false", () => equal(toV6("192.178.66.255", false), "0000:0000:0000:0000:0000:ffff:c0b2:42ff"));

  it("To IPv6, compressedv6 true", () => equal(toV6("192.178.66.255", true), "::ffff:c0b2:42ff"));
  it("From IPv6, compressedv6 true", () => equal(fromV6("::ffff:c0b2:42ff"), "192.178.66.255"));
});