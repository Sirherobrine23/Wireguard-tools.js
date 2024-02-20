# Wireguard-tools.js

Efficiently manage your Wireguard interface right from nodejs, no `wg` required.

other tools are wrappers over `wg`, `wireguard-tools.js` is not like that, it is a `C/C++` addon in which you don't need to have `wg` installed, as this module has full compatibility of its own `wg`.

## CommonJS droping support

With a small disappointment I come to inform you that CommonJS will be ignored in the next updates and will be completely an ESM module, if you don't want to migrate to ESM I recommend staying on version `1.8.1` or even `1.8.3`, which will be the last versions but recent in CommonJS.

## Support to:

- Userspace [(wireguard-go)](https://git.zx2c4.com/wireguard-go/about/) support.
- Maneger wireguard interface (linux and windows create if not exist's).
- Generate `preshared`, `private` and `public` keys.
- [wg-quick](https://man7.org/linux/man-pages/man8/wg-quick.8.html) file support.
- More info and example check [`wiki`](https://sirherobrine23.org/Wireguard/Wireguard-tools.js/wiki).

> [!NOTE]
>
> we have pre-copiled files for:
> - `Linux`: x64/amd64, arm64/aarch64
> - `Windows`: x64, arm64
>
> 1. To manage the Wireguard interfaces in linux, root access is required.
> 1. Another system's require `wireguard-go` [(check this page)](https://github.com/WireGuard/wireguard-go)