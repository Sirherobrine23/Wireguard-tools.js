const { randomInt } = require("node:crypto");

/*
Original repository: https://github.com/arminhammer/node-cidr
LINCENSE: Apache-2.0 license
Fix by @Sirherobrine23
*/
// Common
const invalidChars = /^.*?(?=[\^#%&$\*:<>\?\/\{\|\}[a-zA-Z]).*$/;
function intCommonCidr(ips) {
    const ipInt = ips.sort(), range = ipInt[ipInt.length - 1] - ipInt[0];
    let mask = 0;
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

function padLeft(input, char, min) {
    while (input.length < min)
        input = char + input;
    return input;
}

module.exports.toInt = toInt;
function toInt(ipAddress) {
  return ipAddress.split(".").reduce((p, c, i) => p + parseInt(c) * 256 ** (3 - i), 0);
}

module.exports.toString = toString;
function toString(ipInt) {
    let remaining = ipInt, address = [];
    for (let i = 0; i < 4; i++) {
        if (remaining !== 0) {
            address.push(Math.floor(remaining / 256 ** (3 - i)));
            remaining = remaining % 256 ** (3 - i);
        }
        else {
            address.push(0);
        }
    }
    return address.join(".");
}

module.exports.ipCommonCidr = ipCommonCidr;
/**
 * Get valid cidr
 * @param ips
 * @returns
 */
function ipCommonCidr(ips) {
    if (!ips || ips.filter(s => !!(address(s))).length < 1)
        throw new Error("Insert fist ip");
    const ipInt = ips.map(toInt);
    return intCommonCidr(ipInt);
}

module.exports.toOctets = toOctets;
function toOctets(input) {
  if (typeof input === "number") input = toString(input);
  const [a1, a2, a3, a4] = address(input).split(".").map(x => parseInt(x));
  return [a1, a2, a3, a4];
}

module.exports.reverse = reverse;
/**
 * Returns the reverse lookup hostname for the address.
 * @returns {string}
 */
function reverse(ip) {
    if (typeof ip === "number")
        ip = toString(ip);
    const octets = toOctets(ip);
    return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
}

module.exports.toBinary = toBinary;
/**
 * Returns the binary representation of the address, in string form.
 * @returns {string}
 */
function toBinary(ip) {
    const octets = toOctets(ip);
    let o = [];
    for (let i = 0; i < 4; i++) {
        o[i] = padLeft((octets[i] >>> 0).toString(2), '0', 8);
    }
    return `${o[0]}.${o[1]}.${o[2]}.${o[3]}`;
}

module.exports.toHex = toHex;
/**
 * Provides the hex value of the address.
 * @returns {string}
 */
function toHex(ip) {
    if (typeof ip === 'string') {
        ip = toInt(ip);
    }
    return ip.toString(16);
}

module.exports.nextIp = nextIp;
/**
 * Returns the next adjacent address.
 * @returns {string}
 */
function nextIp(ip) {
    return toString(toInt(ip) + 1);
}

module.exports.previousIp = previousIp;
/**
 * Returns the previous adjacent address.
 * @returns {string}
 */
function previousIp(ip) {
    return toString(toInt(ip) - 1);
}

module.exports.toCidr = toCidr;
/**
 * Get CIDR from ip
 *
 * @param ip - Input ip
 * @returns
 */
function toCidr(ip) {
    if (typeof ip === 'number')
        ip = toString(ip);
    else if (ip.indexOf("/") !== -1) {
        const mask = parseInt(ip.split("/")[1]);
        if (mask >= 0 && mask <= 32)
            return ip;
        else
            ip = address(ip);
    }
    let mask = 8;
    while (true) {
        if (mask >= 32)
            break;
        mask += 4;
        if (includes(ip + "/" + mask, ip))
            break;
    }
    return min(`${ip}/${mask}`) + "/" + mask;
}

module.exports.nextCidr = nextCidr;
function nextCidr(cidr) {
    return `${toString(toInt(address(cidr)) + 2 ** (32 - mask(cidr)))}/${mask(cidr)}`;
}
module.exports.previousCidr = previousCidr;
function previousCidr(cidr) {
    return `${toString(toInt(address(cidr)) - 2 ** (32 - mask(cidr)))}/${mask(cidr)}`;
}

module.exports.validateIp = validateIp;
function validateIp(ip) {
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
module.exports.validateCidr = validateCidr;
function validateCidr(cidr) {
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

module.exports.address = address;
function address(ip) {
    if (!ip || typeof ip === "string" && ip.length < 3)
        throw new Error("Set IP address");
    ip = ip.split("/")[0];
    if (ip.split(".").length !== 4)
        throw new Error("set valid IP address");
    return ip;
}
module.exports.mask = mask;
function mask(ip) {
    if (ip.indexOf("/") === -1)
        ip = ip.concat("/", toCidr(ip).split("/")[1]);
    const mask = parseInt(ip.split("/")[1]);
    if (mask >= 1 && 32 < mask)
        throw new Error("Invalid mask");
    return mask;
}

module.exports.toIntRange = toIntRange;
function toIntRange(cidr) {
    cidr = toCidr(cidr);
    const __min = toInt(min(cidr)), __max = toInt(max(cidr));
    if (__min >= __max)
        throw new Error("Invalid cidr");
    return [__min, __max];
}

module.exports.toRange = toRange;
function toRange(cidr) {
    return [min(cidr), max(cidr)];
}

module.exports.cidrCommonCidr = cidrCommonCidr;
function cidrCommonCidr(cidrs) {
    const ipMap = cidrs.map(x => toIntRange(x));
    const ipInt = Array.prototype.concat.apply([], ipMap).sort();
    return intCommonCidr(ipInt);
}

module.exports.netmask = netmask;
function netmask(cidr) {
    return toString(2 ** 32 - 2 ** (32 - mask(toCidr(cidr))));
}

module.exports.broadcast = broadcast;
function broadcast(cidr) {
    return max(toCidr(cidr));
}

module.exports.min = min;
function min(cidr) {
    cidr = toCidr(cidr);
    const addr = address(cidr);
    const addrInt = toInt(addr);
    const div = addrInt % 2 ** (32 - mask(cidr));
    return div > 0 ? toString(addrInt - div) : addr;
}

module.exports.max = max;
function max(cidr) {
    cidr = toCidr(cidr);
    let initial = toInt(min(cidr));
    let add = 2 ** (32 - mask(cidr));
    return toString(initial + add - 1);
}

module.exports.fistIp = fistIp;
function fistIp(cidr) {
    return toString(toInt(min(toCidr(cidr))) + 1);
}

module.exports.count = count;
function count(cidr) {
    return 2 ** (32 - mask(toCidr(cidr)));
}

module.exports.usable = usable;
function usable(cidr) {
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

module.exports.wildcardmask = wildcardmask;
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
function wildcardmask(cidr) {
    return toString(2 ** (32 - mask(toCidr(cidr))) - 1);
}

module.exports.subnets = subnets;
function subnets(cidr, subMask, limit) {
    // const mainMask: number = mask(cidr);
    const step = 2 ** (32 - subMask), subnets = [];
    let count = toInt(address(cidr)) - step;
    let maxIp = toInt(max(cidr));
    if (limit >= Number.MAX_SAFE_INTEGER)
        throw new Error("Limit is so big");
    else if (isNaN(limit) || !(isFinite(limit)))
        throw new Error("Set valid limit");
    limit = count + limit * step;
    if (limit < maxIp)
        maxIp = limit;
    while (count < maxIp)
        subnets.push(toString(count += step).concat("/", String(subMask)));
    return subnets;
}

module.exports.ips = ips;
function ips(cidr) {
    let ips = [];
    const maxIp = toInt(max(toCidr(cidr)));
    let current = address(cidr);
    while (toInt(current) <= maxIp) {
        ips.push(current);
        current = nextIp(current);
    }
    return ips;
}

module.exports.includes = includes;
/**
 * Check if ip exists in CIDR
 * @param cidr
 * @param ip
 * @returns
 */
function includes(cidr, ip) {
    const ipInt = toInt(ip);
    return ipInt >= toInt(min(cidr)) && ipInt <= toInt(max(cidr));
}

module.exports.randomIp = randomIp;
/**
 * Select random IP from CIDR
 * @param cidr
 * @param drops
 * @returns
 */
function randomIp(cidr, drops) {
    const [minIp, maxIp] = toIntRange(toCidr(cidr));
    let trys = maxIp - minIp;
    while (trys > 0) {
        const ip = toString(randomInt(minIp, maxIp));
        if (!((drops || []).includes(ip)))
            return ip;
        trys--;
    }
    throw new Error("Cannot get random IP or overflow IPs");
}


module.exports.nextIpSequence = nextIpSequence;
/**
 * Get next IP from cidr and skip if exist's else throw if no avaible IP's
 * @param cidr
 * @param skips
 * @returns
 */
function nextIpSequence(cidr, skips) {
    const [minIp, maxIp] = toIntRange(toCidr(cidr));
    let index = 0;
    while ((minIp + index) < maxIp) {
        const ip = toString(minIp + (++index));
        if (!((skips || []).includes(ip)))
            return ip;
    }
    throw new Error("Cannot get random IP or overflow IPs");
}

module.exports.toV6 = toV6;
/**
 * Convert ipv4 in to ipv6
 *
 * @example
 * ```js
 * toV6("192.178.66.255"); // => "0000:0000:0000:0000:0000:ffff:c0b2:42ff"
 * toV6("192.178.66.255", false); // => "0000:0000:0000:0000:0000:ffff:c0b2:42ff"
 * toV6("192.178.66.255", true); // => "::ffff:c0b2:42ff"
 * ```
 */
function toV6(ipv4, compressedv6 = false) {
    if (!ipv4)
        throw new Error("ipv4 is required");
    if (typeof ipv4 !== "string")
        throw new Error("ipv4 must be a string");
    const classValues = ipv4.split(".").map(s => parseInt(s.split("/")[0]) % 256);
    if (classValues.length !== 4)
        throw "Invalid Address";
    const hexaCode = (hexaVal) => hexaVal >= 0 && hexaVal <= 9 ? hexaVal : (hexaVal === 10 ? "a" : (hexaVal === 11 ? "b" : (hexaVal === 12 ? "c" : (hexaVal === 13 ? "d" : (hexaVal === 14 ? "e" : "f")))));
    const str = classValues.reduce((acc, val, ind) => {
        const mod = +val >= 16 ? +val % 16 : +val;
        const modRes = hexaCode(mod);
        const dividerRes = hexaCode(+val >= 16 ? (val - mod) / 16 : 0);
        return ind === 1 ? `${acc}${dividerRes}${modRes}:` : `${acc}${dividerRes}${modRes}`;
    }, "");
    return ("").concat(compressedv6 ? ":" : "0000:0000:0000:0000:0000", (":ffff:"), str);
}

module.exports.fromV6 = fromV6;
/**
 * Convert IPv6 to valid IPv4
 * @param ipv6
 * @returns
 */
function fromV6(ipv6) {
    if (!ipv6 || typeof ipv6 !== "string" || !((["::ffff:", "0000:0000:0000:0000:0000:ffff:", "2002:"]).some(s => ipv6.startsWith(s) && (s === "2002:" ? (ipv6.endsWith("::")) : true))))
        throw new Error("Invalid block input");
    let b64;
    if (ipv6.startsWith("2002:"))
        b64 = ipv6.slice(5, -2);
    else if (ipv6.startsWith("::ffff:"))
        b64 = ipv6.slice(7);
    else
        b64 = ipv6.slice(30);
    b64 = b64.split(":").join("");
    if (b64.split(".").length === 4 && !(b64.split(".").map(s => parseInt(s)).some(s => !(s >= 0 && s <= 255))))
        return b64;
    if (b64.length > 8)
        throw new Error("invalid ipv4 in ipv6");
    return ([
        (parseInt(b64.substring(0, 2), 16) & 0xFF),
        (parseInt(b64.substring(2, 4), 16) & 0xFF),
        (parseInt(b64.substring(4, 6), 16) & 0xFF),
        (parseInt(b64.substring(6, 8), 16) & 0xFF)
    ]).join(".");
}
