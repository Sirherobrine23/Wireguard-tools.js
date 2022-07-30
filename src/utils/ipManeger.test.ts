import * as ipManeger from "./ipManeger";

export default function main() {
  console.log("Random IPs generated from a CIDR: 10.0.0.1/24");
  const results = [];
  let Count = 0;
  while (true) {
    const ip = ipManeger.shuffleIp("10.0.0.1/24");
    results.push({
      ip,
      ipv6: ipManeger.convertToIpv6(ip)
    });
    if (Count++ > 10) break;
  }
  return results;
}