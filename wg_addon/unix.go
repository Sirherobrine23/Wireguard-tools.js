//go:build unix && !linux

package wg_addon

import (
	_ "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	
	"sirherobrine23.com.br/Sirherobrine23/napi-go"
)

// Interface tunnels
var Tuns = map[string]*Tun{}

// Tunnel device
type Tun struct {
	Tun tun.Device
	Dev *device.Device
}

var GetConfig = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	return nil, nil
})

var SetConfig = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	return nil, nil
})

var DeleteInterface = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	return nil, nil
})