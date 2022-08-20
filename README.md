# Wireguard-tools.js

A quick way to use Wireguard with Node.js without having to run the Wireguard tools. We've included some `wg` command patterns to avoid confusion and to maintain a base between the tools.

> **Note**
>
> we have pre-copied files for linux arm64(aarch64) and linux x86_64, any other architecture will be copied the addons for the same one, in which case you will have to have `gcc` or `clang` installed to compile.

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
import { show } from "wireguard-tools.js";
const wireguardInterfaces = show("wg0");
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
