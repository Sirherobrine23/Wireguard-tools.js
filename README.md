# Wireguard-tools.js

Efficiently manage your Wireguard interface right from nodejs, no `wg` required.

other tools are wrappers over `wg`, `wireguard-tools.js` is not like that, it is a `C/C++` addon in which you don't need to have `wg` installed, as this module has full compatibility of its own `wg`.

## Support to:

1. Userpsace [(wireguard-go)](https://git.zx2c4.com/wireguard-go/about/)
2. Maneger wireguard interface (linux create if not exist's).
3. Generate `pre-shared`, `private` and `public` keys.
4. [wg-quick](https://man7.org/linux/man-pages/man8/wg-quick.8.html) file support.

> **Note**
>
> we have pre-copiled files for Windows, MacOS (x64/intel) and Linux (arm64, x86_64) else arch and system require `gcc` or `clang` installed to compile Node addon.
>
> To manage the Wireguard interfaces in linux, root access is required.
>
> Another system's require `wireguard-go` [(check this page)](https://github.com/WireGuard/wireguard-go)

## Examples

Moved to `examples` folder