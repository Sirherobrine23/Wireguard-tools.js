# Wireguard-tools.js

Efficiently manage your Wireguard interface right from nodejs, no `wg` required.

other tools are wrappers over `wg`, `wireguard-tools.js` is not like that, it is a `C/C++` addon in which you don't need to have `wg` installed, as this module has full compatibility of its own `wg`.

## Support to:

- Userspace [(wireguard-go)](https://git.zx2c4.com/wireguard-go/about/) support.
- Maneger wireguard interface (linux and windows create if not exist's).
- Generate `pre-shared`, `private` and `public` keys.
- [wg-quick](https://man7.org/linux/man-pages/man8/wg-quick.8.html) file support.
- More info and example check [`docs`](docs/README.md) folder.

> **Note**
>
> we have pre-copiled files for:
> - `Windows`: x64, arm64
> - `MacOS`: x64/intel, arm64
> - `Linux`: x64/amd64, arm64
>
> else arch and system require copiler supported by `node-gyp` installed to compile Node addon.
>
> 1. To manage the Wireguard interfaces in linux, root access is required.
> 1. Windows user are `wireguard-nt` dll files includes in module
> 1. Another system's require `wireguard-go` [(check this page)](https://github.com/WireGuard/wireguard-go)
