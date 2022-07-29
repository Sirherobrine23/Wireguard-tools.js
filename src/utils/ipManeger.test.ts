import * as ipManeger from "./ipManeger";

export default function main() {
  console.log("Random IPs generated from a CIDR: 10.0.0.1/24");
  let Count = 0;
  while (true) {
    const ips = [ipManeger.shuffleIp("10.0.0.1/24"), ipManeger.shuffleIp("10.0.0.1/24")];
    console.log("\nShuffle IP: %s, %s", ...ips);
    console.log("IPV6: %s", ipManeger.convertToIpv6(ips[0]));
    if (Count++ > 10) break;
  }
}