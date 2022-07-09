export type ipObject = {
  type: "ipv4"|"ipv6",
  subnet: number,
  ip: string,
};
export type interfaceObject = {
  portListen?: number,
  private: string,
  ip: ipObject[],
  post?: {up?: string[], down?: string[]},
  DNS?: string[]
};
export type peerConfig = {
  public: string,
  ip: ipObject[],
  allowIp: ipObject[],
  preshared?: string,
  Endpoint?: {host: string, port: number},
  commend?: string
};

export type wireguardObject = {
  peers: peerConfig[],
  interface: interfaceObject
};

export async function parseConfig(configString: string): Promise<wireguardObject> {
  const peers: peerConfig[] = [];
  ([...configString.matchAll(/\[Peer\]([\s\S]+)\n?/g)]).map(x => x[1]).forEach(x => {
    for (let l of x.split(/\[Peer\]/).filter(x => !!x)) {
      let peer: peerConfig = {
        ip: [],
        allowIp: [],
        public: "",
      }
      let pub = l.match(/PublicKey\s+=\s+(.*)\n?/);
      if (!!pub) peer.public = pub[1].trim();

      let pre = l.match(/PresharedKey\s+=\s+(.*)\n?/);
      if (!!pre) peer.preshared = pre[1].trim();

      let Endpoint = l.match(/Endpoint\s+=\s+(.*)\n?/);
      if (!!Endpoint) peer.Endpoint = {
        host: Endpoint[1].split(":")[0],
        port: parseInt(Endpoint[1].split(":")[1]||"51820")
      };

      let allowIps = l.match(/AllowedIPs\s+=\s+(.*)\n?/);
      if (!!allowIps) {
        allowIps[1].split(",").forEach(ip => {
          const [ip2, sub] = ip.trim().split("/");
          peer.allowIp.push({ip: ip2, subnet: parseInt(sub), type: !/:/.test(ip)?"ipv4":"ipv6"});
        });
      }
      let ips = l.match(/Address\s+=\s+(.*)\n?/);
      if (!!ips) {
        ips[1].split(",").forEach(ip => {
          const [ip2, sub] = ip.trim().split("/");
          peer.allowIp.push({ip: ip2, subnet: parseInt(sub), type: !/:/.test(ip)?"ipv4":"ipv6"});
        });
      }
      peers.push(peer);
    }
  })
  configString = configString.replace(/\[Peer\]([\s\S]+)\n?/g, "");

  let inter = (([...configString.matchAll(/\[Interface\]\n([\S\s]+)/g)][0])||["", null])[1];
  if (!inter) throw new Error("Invalid wireguard config");
  const interfaceConfig: interfaceObject = {private: "", ip: []}

  let portListen = inter.match(/ListenPort\s+?=\s+?([0-9]+)\n?/);
  if (!!portListen) interfaceConfig.portListen = parseInt(portListen[1].trim());

  let PrivateKey = inter.match(/PrivateKey\s+?=\s+?(.*)\n?/);
  if (!!PrivateKey) interfaceConfig.private = PrivateKey[1].trim();

  let DNS = inter.match(/DNS\s+?=\s+?(.*)\n?/);
  if (!!DNS) interfaceConfig.DNS = DNS[1].trim().split(",").map(x => x.trim());

  for (let ip of [...inter.matchAll(/Address\s+?=\s+?(.*)/g)]) {
    ip[1].split(",").forEach(x => {
      const [ip, sub] = x.trim().split("/");
      interfaceConfig.ip.push({ip: ip, subnet: parseInt(sub), type: !/:/.test(ip)?"ipv4":"ipv6"})
    });
  }

  return { interface: interfaceConfig, peers };
}

export function createConfig(input: wireguardObject): string {
  let config = "";
  config+="[Interface]\n";
  if (!!input?.interface.portListen) config += `ListenPort = ${input?.interface.portListen}\n`;
  config += `PrivateKey = ${input.interface.private}\n`;
  if (!!input.interface?.post?.up) config += `PostUp = ${input.interface?.post?.up.join("; ")}\n`;
  if (!!input.interface?.post?.down) config += `PostDown = ${input.interface?.post?.down.join("; ")}\n`;
  config += `Address = ${input.interface?.ip.map(x => x.ip+"/"+x.subnet).join(", ")}\n`;
  if (!!input.interface.DNS) config += `DNS = ${input.interface.DNS.join(", ")}\n`;

  input.peers.forEach(peer => {
    config += "\n";
    if (!!peer.commend) config += `### ${peer.commend}\n`;
    config += "[Peer]\n";
    if (!!peer.preshared) config += `PresharedKey = ${peer.preshared}\n`;
    config += `PublicKey = ${peer.public}\n`;
    if (peer.allowIp.length > 0) config += `AllowedIPs = ${peer.allowIp.map(x => x.ip+"/"+x.subnet).join(", ")}\n`;
    if (peer.ip.length > 0) config += `Address = ${peer.ip.map(x => x.ip+"/"+x.subnet).join(", ")}\n`;
    if (!!peer.Endpoint) config += `Endpoint = ${peer.Endpoint.host}:${peer.Endpoint.port}\n`;
  });

  return config;
}