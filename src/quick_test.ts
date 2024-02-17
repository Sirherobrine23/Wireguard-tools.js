import test from "node:test";
import assert from "node:assert";
import { QuickConfig, parse, stringify } from "./quick.js";

const StaticConfig = `[Interface]
ListenPort = 38451
Address = 10.144.0.1/32, 192.160.0.1/32, 10.80.0.1/32, 10.48.0.1/32, 10.0.0.1/32, 10.208.0.1/32, 10.64.0.1/32, 10.176.0.1/32, 10.160.0.1/32, 10.96.0.1/32, 2002:0A90:0001::/128, 2002:C0A0:0001::/128, 2002:0A50:0001::/128, 2002:0A30:0001::/128, 2002:0A00:0001::/128, 2002:0AD0:0001::/128, 2002:0A40:0001::/128, 2002:0AB0:0001::/128, 2002:0AA0:0001::/128, 2002:0A60:0001::/128
PrivateKey = 2Ll/2LCXDlLVZcBCBZ6QeXB4qEF+bTzmuOBxnpu57WY=
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m  addrtype ! --dst-type LOCAL -j REJECT

[Peer]
PublicKey = PYKXjQa4mzTNS5ICMTOFNsyLFKV3y+M9bRVaTBfzSiE=
PresharedKey = d4TTwQYZEI5Nx6XClzjqDGXyzgg9EiZxDW56Ovp4B6U=
AllowedIPs = 10.152.60.241/32, 192.168.15.121/32, 2002:0A98:3CF1::/128, 2002:C0A8:0F79::/128

[Peer]
PublicKey = bWCWdAfi8UcEl7fJkHwnnVhUB1dahEl2IoznIdLAOHo=
PresharedKey = NDwaRu4JCE3PiuDUPTcTyXyV8CaHaqR5TJxAF9DOzJg=
AllowedIPs = 10.50.11.146/32, 10.10.192.254/32, 2002:0A32:0B92::/128, 2002:0A0A:C0FE::/128

[Peer]
PublicKey = 15PMkuIeQNM9AlknHb+c10y8e3fzOihZJpuD23y+d0c=
AllowedIPs = 10.88.198.220/32, 192.168.15.112/32, 2002:0A58:C6DC::/128, 2002:C0A8:0F70::/128`;

const StaticConfigJson: QuickConfig = {
  privateKey: "2Ll/2LCXDlLVZcBCBZ6QeXB4qEF+bTzmuOBxnpu57WY=",
  portListen: 38451,
  PostUp: [
    "iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m  addrtype ! --dst-type LOCAL -j REJECT"
  ],
  PreDown: [
    "iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT"
  ],
  Address: [
    "10.144.0.1/32",        "192.160.0.1/32",
    "10.80.0.1/32",         "10.48.0.1/32",
    "10.0.0.1/32",          "10.208.0.1/32",
    "10.64.0.1/32",         "10.176.0.1/32",
    "10.160.0.1/32",        "10.96.0.1/32",
    "2002:0A90:0001::/128", "2002:C0A0:0001::/128",
    "2002:0A50:0001::/128", "2002:0A30:0001::/128",
    "2002:0A00:0001::/128", "2002:0AD0:0001::/128",
    "2002:0A40:0001::/128", "2002:0AB0:0001::/128",
    "2002:0AA0:0001::/128", "2002:0A60:0001::/128"
  ],
  peers: {
    "PYKXjQa4mzTNS5ICMTOFNsyLFKV3y+M9bRVaTBfzSiE=": {
      presharedKey: "d4TTwQYZEI5Nx6XClzjqDGXyzgg9EiZxDW56Ovp4B6U=",
      allowedIPs: [
        "10.152.60.241/32",
        "192.168.15.121/32",
        "2002:0A98:3CF1::/128",
        "2002:C0A8:0F79::/128"
      ]
    },
    "bWCWdAfi8UcEl7fJkHwnnVhUB1dahEl2IoznIdLAOHo=": {
      presharedKey: "NDwaRu4JCE3PiuDUPTcTyXyV8CaHaqR5TJxAF9DOzJg=",
      allowedIPs: [
        "10.50.11.146/32",
        "10.10.192.254/32",
        "2002:0A32:0B92::/128",
        "2002:0A0A:C0FE::/128"
      ]
    },
    "15PMkuIeQNM9AlknHb+c10y8e3fzOihZJpuD23y+d0c=": {
      allowedIPs: [
        "10.88.198.220/32",
        "192.168.15.112/32",
        "2002:0A58:C6DC::/128",
        "2002:C0A8:0F70::/128"
      ]
    }
  }
};

test("Wireguard quick config", async t => {
  await t.test("Stringify", async () => {
    const wgConfig = stringify(StaticConfigJson);
    assert.strictEqual(wgConfig, StaticConfig);
  });
  await t.test("Parse", async () => {
    const wgConfig = parse(StaticConfig);
    assert.deepEqual(wgConfig, StaticConfigJson);
  });
});