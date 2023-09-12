export function toInt(ipAddress: string): number;
export function toString(ipInt: number): string;
/**
 * Get valid cidr
 * @param ips
 * @returns
 */
export function ipCommonCidr(ips: [string, ...(string[])]): string;
export function toOctets(input: string | number): [number, number, number, number];
/**
 * Returns the reverse lookup hostname for the address.
 * @returns {string}
 */
export function reverse(ip: string | number): string;
/**
 * Returns the binary representation of the address, in string form.
 * @returns {string}
 */
export function toBinary(ip: string | number): string;
/**
 * Provides the hex value of the address.
 * @returns {string}
 */
export function toHex(ip: string | number): string;
/**
 * Returns the next adjacent address.
 * @returns {string}
 */
export function nextIp(ip: string): string;
/**
 * Returns the previous adjacent address.
 * @returns {string}
 */
export function previousIp(ip: string): string;
/**
 * Get CIDR from ip
 *
 * @param ip - Input ip
 * @returns
 */
export function toCidr(ip: string | number): string;
export function nextCidr(cidr: string): string;
export function previousCidr(cidr: string): string;
export function validateIp(ip: string): string | null;
export function validateCidr(cidr: string): string | null;
export function address(ip: string): string;
export function mask(ip: string): number;
export function toIntRange(cidr: string): [number, number];
export function toRange(cidr: string): [string, string];
export function cidrCommonCidr(cidrs: string[]): string;
export function netmask(cidr: string): string;
export function broadcast(cidr: string): string;
export function min(cidr: string): string;
export function max(cidr: string): string;
export function fistIp(cidr: string): string;
export function count(cidr: string): number;
export function usable(cidr: string): string[];
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
export function wildcardmask(cidr: string): string;
export function subnets(cidr: string, subMask: number, limit: number): string[];
export function ips(cidr: string): string[];
/**
 * Check if ip exists in CIDR
 * @param cidr
 * @param ip
 * @returns
 */
export function includes(cidr: string, ip: string): boolean;
/**
 * Select random IP from CIDR
 * @param cidr
 * @param drops
 * @returns
 */
export function randomIp(cidr: string, drops?: string[]): string;
/**
 * Get next IP from cidr and skip if exist's else throw if no avaible IP's
 * @param cidr
 * @param skips
 * @returns
 */
export function nextIpSequence(cidr: string, skips: string[]): string;
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
export function toV6(ipv4: string, compressedv6?: boolean): string;
/**
 * Convert IPv6 to valid IPv4
 * @param ipv6
 * @returns
 */
export function fromV6(ipv6: string): string;
