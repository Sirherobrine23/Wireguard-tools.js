import { randomInt } from "node:crypto";

/*
Original repository: https://github.com/arminhammer/node-cidr
LINCENSE: Apache-2.0 license
Fix by @Sirherobrine23
*/
// Common
const invalidChars = /^.*?(?=[\^#%&$\*:<>\?\/\{\|\}[a-zA-Z]).*$/;

function intCommonCidr(ips: number[]): string {
  const ipInt = ips.sort();
  let mask = 0;
  const range = ipInt[ipInt.length - 1] - ipInt[0];
  let baseIp = ipInt[0];
  for (let i = 0; i <= 32; i++) {
    mask = 32 - i;
    const exp = 2 ** (32 - mask);
    if (exp - 1 >= range) {
      if (ipInt[0] % exp != 0) {
        baseIp = ipInt[0] - ipInt[0] % exp;
      }
      if (ipInt[ipInt.length - 1] > baseIp + exp) {
        mask--;
      }
      break;
    }
  }
  return `${toString(baseIp)}/${mask}`;
}

function padLeft(input: string, char: string, min: number): string {
  while (input.length < min) {
    input = char + input;
  }
  return input;
}

// IP Address methods

export function toInt(ipAddress: string): number {
  return ipAddress.split('.').reduce((p: number, c: string, i: number) => p + parseInt(c) * 256 ** (3 - i), 0);
}

export function toString(ipInt: number): string {
  let remaining = ipInt;
  let address = [];
  for (let i = 0; i < 4; i++) {
    if (remaining != 0) {
      address.push(Math.floor(remaining / 256 ** (3 - i)));
      remaining = remaining % 256 ** (3 - i);
    } else {
      address.push(0);
    }
  }
  return address.join('.');
}

/**
 * Get valid cidr
 * @param ips
 * @returns
 */
export function ipCommonCidr(ips: [string, ...(string[])]): string {
  if (!ips || ips.filter(s => !!(address(s))).length < 1) throw new Error("Insert fist ip");
  const ipInt = ips.map(toInt);
  return intCommonCidr(ipInt);
}

export function toOctets(input: string | number): [number, number, number, number] {
  if (typeof input === "number") input = toString(input);
  const [a1, a2, a3, a4] = address(input).split(".").map(x => parseInt(x));
  return [a1, a2, a3, a4];
}

/**
 * Returns the reverse lookup hostname for the address.
 * @returns {string}
 */
export function reverse(ip: string | number): string {
  if (typeof ip === "number") ip = toString(ip);
  const octets = toOctets(ip);
  return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
}
/**
 * Returns the binary representation of the address, in string form.
 * @returns {string}
 */
export function toBinary(ip: string | number): string {
  const octets = toOctets(ip);
  let o = [];
  for (let i = 0; i < 4; i++) {
    o[i] = padLeft((octets[i] >>> 0).toString(2), '0', 8);
  }
  return `${o[0]}.${o[1]}.${o[2]}.${o[3]}`;
}

/**
 * Provides the hex value of the address.
 * @returns {string}
 */
export function toHex(ip: string | number): string {
  if (typeof ip === 'string') {
    ip = toInt(ip);
  }
  return ip.toString(16);
}

/**
 * Returns the next adjacent address.
 * @returns {string}
 */
export function nextIp(ip: string): string {
  return toString(toInt(ip) + 1);
}

/**
 * Returns the previous adjacent address.
 * @returns {string}
 */
export function previousIp(ip: string): string {
  return toString(toInt(ip) - 1);
}

/**
 * Get CIDR from ip
 *
 * @param ip - Input ip
 * @returns
 */
export function toCidr(ip: string | number): string {
  if (typeof ip === 'number') ip = toString(ip);
  else if (ip.indexOf("/") !== -1) {
    const mask = parseInt(ip.split("/")[1]);
    if (mask >= 0 && mask <= 32) return ip;
    else ip = address(ip);
  }
  let mask = 8;
  while (true) {
    if (mask >= 32) break;
    mask += 4;
    if (includes(ip+"/"+mask, ip)) break;
  }
  return min(`${ip}/${mask}`)+"/"+mask;
}

export function nextCidr(cidr: string): string {
  return `${toString(toInt(address(cidr)) + 2 ** (32 - mask(cidr)))}/${mask(cidr)}`;
}

export function previousCidr(cidr: string): string {
  return `${toString(toInt(address(cidr)) - 2 ** (32 - mask(cidr)))}/${mask(cidr)}`;
}

export function validateIp(ip: string): string | null {
  if (invalidChars.test(ip))
    return 'Invalid IP: illegal character';

  const octets = ip.split('.');
  if (octets.length !== 4)
    return 'Invalid address: Not enough quads';
  for (let i = 0; i < octets.length; i++) {
    const int = parseInt(octets[i]);
    if (isNaN(int))
      return 'Invalid IP: Invalid quad';
    if (int > 255)
      return 'Invalid IP: quad too large';
  }
  return null;
}

// CIDR Methods
export function validateCidr(cidr: string): string | null {
  const ip = address(cidr);
  const ipValid = validateIp(ip);
  if (ipValid !== null)
    return ipValid;
  const cidrMask = mask(cidr);
  console.log('cidrMask:', cidrMask, cidr);
  if (cidrMask > 32)
    return 'Invalid: mask cannot be more than 32';
  if (cidrMask < 0)
    return 'Invalid: mask cannot be less than 0';
  if (isNaN(cidrMask))
    return 'Invalid: mask must be a positive integer';
  if (ip !== min(cidr))
    return `Invalid: CIDR better expressed as ${min(cidr)}/${mask(cidr)}`;
  return null;
}

export function address(ip: string): string {
  if (!ip || typeof ip === "string" && ip.length < 3) throw new Error("Set IP address");
  ip = ip.split("/")[0];
  if (ip.split(".").length !== 4) throw new Error("set valid IP address");
  return ip;
}

export function mask(ip: string) {
  if (ip.indexOf("/") === -1) ip = ip.concat("/", toCidr(ip).split("/")[1]);
  const mask = parseInt(ip.split("/")[1]);
  if (mask >= 1 && 32 < mask) throw new Error("Invalid mask");
  return mask;
}

export function toIntRange(cidr: string): [number, number] {
  cidr = toCidr(cidr);
  const __min = toInt(min(cidr)), __max = toInt(max(cidr));
  if (__min >= __max) throw new Error("Invalid cidr");
  return [ __min, __max ];
}

export function toRange(cidr: string): [string, string] {
  return [min(cidr), max(cidr)];
}

export function cidrCommonCidr(cidrs: string[]): string {
  const ipMap = cidrs.map(x => toIntRange(x));
  const ipInt = Array.prototype.concat.apply([], ipMap).sort();
  return intCommonCidr(ipInt);
}

export function netmask(cidr: string): string {
  return toString(2 ** 32 - 2 ** (32 - mask(toCidr(cidr))));
}

export function broadcast(cidr: string): string {
  return max(toCidr(cidr));
}

export function min(cidr: string): string {
  cidr = toCidr(cidr);
  const addr = address(cidr);
  const addrInt = toInt(addr);
  const div = addrInt % 2 ** (32 - mask(cidr));
  return div > 0 ? toString(addrInt - div) : addr;
}

export function max(cidr: string): string {
  cidr = toCidr(cidr);
  let initial: number = toInt(min(cidr));
  let add = 2 ** (32 - mask(cidr));
  return toString(initial + add - 1);
}

export function fistIp(cidr: string): string {
  return toString(toInt(min(toCidr(cidr)))+1);
}

export function count(cidr: string): number {
  return 2 ** (32 - mask(toCidr(cidr)));
}

export function usable(cidr: string): string[] {
  cidr = toCidr(cidr);
  const result = [];
  let start = toInt(min(cidr)) + 1;
  const stop = toInt(max(cidr));
  while (start < stop) {
    result.push(toString(start));
    start += 1;
  }
  return result;
}

/**
 * get representation of subnet attach's ip's
 *
 * @example
 * ```js
 * wildcardmask("0.0.0.0/0"); // => "255.255.255.255"
 * wildcardmask("127.0.0.0/1"); // => "127.255.255.255"
 * wildcardmask("192.0.0.0/24"); // => "0.0.0.255"
 * ```
 *
 * @param cidr
 * @returns
 */
export function wildcardmask(cidr: string): string {
  return toString(2 ** (32 - mask(toCidr(cidr))) - 1);
}

export function subnets(cidr: string, subMask: number, limit: number): string[] {
  // const mainMask: number = mask(cidr);
  const step = 2 ** (32 - subMask), subnets = [];
  let count = toInt(address(cidr)) - step;
  let maxIp = toInt(max(cidr));

  if (limit >= Number.MAX_SAFE_INTEGER) throw new Error("Limit is so big");
  else if (isNaN(limit) || !(isFinite(limit))) throw new Error("Set valid limit");
  limit = count + limit * step;
  if (limit < maxIp) maxIp = limit;
  while (count < maxIp) subnets.push(toString(count += step).concat("/", String(subMask)));
  return subnets;
}

export function ips(cidr: string): string[] {
  let ips: string[] = [];
  const maxIp = toInt(max(toCidr(cidr)));
  let current: string = address(cidr);
  while (toInt(current) <= maxIp) {
    ips.push(current);
    current = nextIp(current);
  }
  return ips;
}

/**
 * Check if ip exists in CIDR
 * @param cidr
 * @param ip
 * @returns
 */
export function includes(cidr: string, ip: string): boolean {
  const ipInt = toInt(ip);
  return ipInt >= toInt(min(cidr)) && ipInt <= toInt(max(cidr));
}

/**
 * Select random IP from CIDR
 * @param cidr
 * @param drops
 * @returns
 */
export function randomIp(cidr: string, drops?: string[]): string {
  const [minIp, maxIp] = toIntRange(toCidr(cidr));
  while (true) {
    const ip = toString(randomInt(minIp, maxIp));
    if (!((drops||[]).includes(ip))) return ip;
  }
}

/**
 * Convert ipv4 to ipv6
 *
 * @example
 * ```js
 * toV6("192.178.66.255"); // => "0000:0000:0000:0000:0000:ffff:c0b2:42ff"
 * toV6("192.178.66.255", false); // => "0000:0000:0000:0000:0000:ffff:c0b2:42ff"
 * toV6("192.178.66.255", true); // => "::ffff:c0b2:42ff"
 * ```
 */
export function toV6(ipv4: string, compressedv6: boolean = false) {
  if (!ipv4) throw new Error("ipv4 is required");
  if (typeof ipv4 !== "string") throw new Error("ipv4 must be a string");
  const classValues = ipv4.split(".").map(s => parseInt(s.split("/")[0]) % 256);
  if (classValues.length !== 4) throw "Invalid Address";
  const hexaCode = (hexaVal: number) => hexaVal >= 0 && hexaVal <= 9 ? hexaVal : (hexaVal === 10 ? "a" : (hexaVal === 11 ? "b" : (hexaVal === 12 ? "c" : (hexaVal === 13 ? "d" : (hexaVal === 14 ? "e" : "f")))));
  const str = classValues.reduce((acc, val, ind) => {
    const mod = +val >= 16 ? +val%16 : +val;
    const modRes = hexaCode(mod);
    const dividerRes = hexaCode(+val >= 16 ? (val-mod)/16 : 0);
    return ind === 1 ? `${acc}${dividerRes}${modRes}:`:`${acc}${dividerRes}${modRes}`;
  }, "");
  return ("").concat(compressedv6 ? ":" : "0000:0000:0000:0000:0000", (":ffff:"), str);
}

/**
 * Convert IPv6 to valid IPv4
 * @param ipv6
 * @returns
 */
export function fromV6(ipv6: string) {
  if (!ipv6 || typeof ipv6 !== "string" || !((["::ffff:", "0000:0000:0000:0000:0000:ffff:", "2002:"]).some(s => ipv6.startsWith(s) && (s === "2002:" ? (ipv6.endsWith("::")) : true)))) throw new Error("Invalid block input");
  let b64: string;
  if (ipv6.startsWith("2002:")) b64 = ipv6.slice(5, -2);
  else if (ipv6.startsWith("::ffff:")) b64 = ipv6.slice(7);
  else b64 = ipv6.slice(30);
  b64 = b64.split(":").join("");
  if (b64.split(".").length === 4 && !(b64.split(".").map(s => parseInt(s)).some(s => !(s >= 0 && s <= 255)))) return b64;
  if (b64.length > 8) throw new Error("invalid ipv4 in ipv6");
  return ([
    (parseInt(b64.substring(0, 2), 16) & 0xFF),
    (parseInt(b64.substring(2, 4), 16) & 0xFF),
    (parseInt(b64.substring(4, 6), 16) & 0xFF),
    (parseInt(b64.substring(6, 8), 16) & 0xFF)
  ]).join(".");
}