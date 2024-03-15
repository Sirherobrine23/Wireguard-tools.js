//go:build linux || darwin || freebsd || openbsd

package main

import (
	_ "golang.zx2c4.com/wireguard/ipc"
	_ "unsafe"
)

//go:linkname socketDirectory golang.xz2c4.com/wireguard/ipc.socketDirectory
var socketDirectory = "/var/run/wireguard"
