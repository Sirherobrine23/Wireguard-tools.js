# Wireguard-tools for Nodejs

Manage your Wireguard interfaces directly from Node.js without any wrappers over `wg` or `wg-quick`

> [!WARNING]
> Require cmake and tools (GCC/GCC++, clang or Visual Studio) to build this addon
>
> New versions does't include prebuilt binaries

```js
import { setConfig, getConfig, key, Config } from "../index.js"

const tunName = process.platform === "darwin" ? "utun10" : "wg3" // Tunnel name, in MacOS/Darwin require start with utun prefix
let currentConfig: Config
try {
  currentConfig = await getConfig(tunName) // Check if exists tun
} catch {
  // Create new wireguard tun
  currentConfig = {
    name: tunName,
    privateKey: await key.privateKey(),
    portListen: 5820,
    address: [
      "10.66.66.1/24"
    ],
    peers: {}
  }
}

// Add new Peer
const peerPrivate = await key.privateKey()
currentConfig.peers[key.publicKey(peerPrivate)] = {
  presharedKey: await key.presharedKey(),
  allowedIPs: [
    "10.66.66.2/24"
  ]
}

// Deploy new Config
await setConfig(currentConfig)
```

## Licences

- `Wireguard-tools.js`: GPL-3.0

### Wireguard

- `Embeddable-wg-library`: LGPL-2.1+.
- `Wireguard-nt`: GPL-2.0
- `Wireguard-go`: MIT