# Wireguard-tools.js

A quick way to use Wireguard with Node.js without having to run the Wireguard tools. We've included some `wg` command patterns to avoid confusion and to maintain a base between the tools.

In addition to having some basic utilities already integrated:

- Keygen: Generate private and public keys and also a pre-shared key.
- Config file: You can generate files for Wireguard directly from here and you can transform a configuration file into a JSON.

To manage Wireguard interfaces:

- Create a new Wireguard network interface and configure it with the provided information.
- Delete Interface.
- Get the peers along with the interface and peer information.

## Example

Parse wireguard configuration file:

```ts
import { readFileSync } from "node:fs";
import { utils } from "wireguard-tools.js";
const configFile = readFileSync("/etc/wireguard/wg0.conf", "utf8");
const configJson = utils.config.parseConfig(configFile);
console.log("Config file JSON:\n%o", configJson.data);
```

Create Config:

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

or

> **Note**
>
> To save to wireguard's default directory (`/etc/wireguard`), it is necessary to have root access or a user with write permissions on the directory.

```ts
import { utils } from "wireguard-tools.js";
utils.config.writeConfig({
  interface: {
    private: "CEOntDE9saQaHLhD/WzZuYky3+elOfnBUCXoSveD3kc=",
    public: "xaZtpi3VCkBMhSTKM6jl/YjPJ370iYpBlLYwSyZ3W08=",
    address: [
      {
        ip: "10.0.0.5",
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
}, "wg0");
```

Get Current peers and Statistics:

```ts
import { getAllPeersAndInterface } from "wireguard-tools.js";
const wireguardInterfaces = getAllPeersAndInterface();
// Wg0 is the interface name.
console.log("Wg0:\n%o", wireguardInterfaces["wg0"]);
```
