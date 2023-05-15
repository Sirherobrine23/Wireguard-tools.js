# Wireguard-tools.js

A quick way to use Wireguard with Node.js without having to run the Wireguard tools. We've included some `wg` command patterns to avoid confusion and to maintain a base between the tools.

> **Note**
>
> we have pre-copied files for Windows, MacOS (x64/intel) and Linux (arm64, x86_64), else require `gcc` or `clang` installed to compile Node addon.

With this module it is possible to:

- Add/Remove a Wireguard interface.
- Add/Remove/Modify `peers` for an interface.
- Add IPs to the interface.
- Create `pre-shared`, `private` and `public` keys.
- Write the Wireguard configuration file and convert it to JSON format.

## External LGPL Licence

This project works because with of [Wireguard embeddable library](https://github.com/WireGuard/wireguard-tools/tree/master/contrib/embeddable-wg-library).

## Example

> **Note**
>
> To manage the Wireguard interfaces, root access is required.

### Get Current peers and Statistics

```ts
import { parseWgDevice } from "wireguard-tools.js";
const wireguardInterfaces = parseWgDevice("wg0");
// Wg0 is the interface name.
console.log("Wg0:\n%o", wireguardInterfaces);
```

# Add/Update Wireguard interface

```ts
import { addDevice, parseWgDevice } from "wireguard-tools.js";
addDevice("wg0", {
  publicKey: "string",
  privateKey: "string",
  portListen: 27301,
  Address: [
    "1.1.1.1/32",
    "8.8.8.8/32"/** Mark this peer to be removed, any changes remove this option */
  ],
  replacePeers: true,
  peers: {
    "publicKeyPeer": {
      removeMe: false,
      presharedKey: "string",
      keepInterval: 5,
      endpoint: "google.com:27301",
      allowedIPs: [
        "8.8.8.8",
        "8.8.4.4."
      ]
    }
  }
});
const wireguardInterfaces = parseWgDevice("wg0");
// Wg0 is the interface name.
console.log("Wg0:\n%o", wireguardInterfaces);
```

### Parse wireguard configuration file

```ts
import { readFileSync } from "node:fs";
import { utils } from "wireguard-tools.js";
const configFile = readFileSync("/etc/wireguard/wg0.conf", "utf8");
const configJson = utils.config.parseConfig(configFile);
console.log("Config file JSON:\n%o", configJson.data);
```

### Create Config

```ts
import { utils } from "wireguard-tools.js";
const wireguardConfig = utils.config.writeConfig({
  interface: {
    private: "CEOntDE9saQaHLhD/WzZuYky3+elOfnBUCXoSveD3kc=",
    public: "xaZtpi3VCkBMhSTKM6jl/YjPJ370iYpBlLYwSyZ3W08=",
    address: [
      {
        ip: "10.0.0.1",
        subnet: 24
      }
    ]
  },
  peer: {
    "tF4YxTqLIJdNQcqvz1jtIF993zSk79hP+zdBxQlaowA=": {
      Keepalive: 25,
      Endpoint: {
        host: "wireguard.example.com",
        port: 51820
      },
    }
  }
});
console.log("Config file:\n%s", wireguardConfig);
```
