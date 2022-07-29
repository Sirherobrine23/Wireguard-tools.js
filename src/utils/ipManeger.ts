import * as crypto from "node:crypto";
import * as nodeCidr from "../lib/node-cidr";

export function shuffleIp(cidr: string): string {
  const ips = nodeCidr.cidr.ips(cidr);
  for (let i = ips.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, ips.length-1);
    const temp = ips[i];
    ips[i] = ips[j];
    ips[j] = temp;
  }
  return ips[crypto.randomInt(Math.random() > 0.6 ? 0:Math.floor((ips.length-1)-Math.random()*ips.length/2), ips.length-1)];
}

export function convertToIpv6(ipv4: string) {
  if (!ipv4) throw new Error("ipv4 is required");
  if (typeof ipv4 !== "string") throw new Error("ipv4 must be a string");
  const classValues = ipv4.split(".");
  if(classValues.length !== 4) throw "Invalid Address";
  const hexaCode = (hexaVal: number) => {
    if (hexaVal === 10) return "A";
    else if (hexaVal === 11) return "B";
    else if (hexaVal === 12) return "C";
    else if (hexaVal === 13) return "D";
    else if (hexaVal === 14) return "E";
    else if (hexaVal === 15) return "F";
    else return hexaVal;
  }
  const str = classValues.reduce((acc, val, ind) => {
    const mod = +val >= 16 ? +val%16 : +val;
    const divider = +val >= 16 ? (parseFloat(val)-mod)/16 : 0;
    const modRes = hexaCode(mod);
    const dividerRes = hexaCode(divider);
    return ind === 1 ? `${acc}${dividerRes}${modRes}:`:`${acc}${dividerRes}${modRes}`;
  }, "");
  return `2002:${str}::`;
}