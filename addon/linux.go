//go:build linux

package addon

import (
	"errors"

	"github.com/abhisekp/napi-go"
	"github.com/abhisekp/napi-go/js"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// args: [Name: string]
func GetInterface(env napi.Env, info napi.CallbackInfo) napi.Value {
	args, err := processArgs(env, info)
	if err != nil {
		napi.Throw(env, js.AsEnv(env).ValueOf(err.Error()).Value)
		return nil
	}

	promise, _ := napi.CreatePromise(env)
	asyncResourceName, _ := napi.CreateStringUtf8(env, "addon/GetInterface")
	devInfo := &Config{}

	var worker napi.AsyncWork
	worker, _ = napi.CreateAsyncWork(env, nil, asyncResourceName,
		func(env napi.Env) {
			if len(args) == 0 {
				err = errors.New("Set interface name")
				return
			}

			// Interface name
			interfaceName, _ := napi.GetValueStringUtf8(args[0].Env.Env, args[0].Value)

			// Get client to wireguard
			var client *wgctrl.Client
			if client, err = wgctrl.New(); err != nil {
				return
			}
			defer client.Close()

			// Get config
			var dev *wgtypes.Device
			if dev, err = client.Device(interfaceName); err != nil {
				return
			}

			devInfo.PublicKey = dev.PublicKey.String()
			devInfo.PrivateKey = dev.PrivateKey.String()
			devInfo.PortListen = dev.ListenPort
			devInfo.Fwmark = dev.FirewallMark
			devInfo.Peers = map[string]*Peer{}
			for _, peer := range dev.Peers {
				devInfo.Peers[peer.PublicKey.String()] = &Peer{
					PresharedKey:  peer.PresharedKey.String(),
					LastHandshake: peer.LastHandshakeTime,
					KeepInterval:  int(peer.PersistentKeepaliveInterval.Seconds()),
					TxByte:        int(peer.TransmitBytes),
					RxByte:        int(peer.ReceiveBytes),
					AllowedIPs:    peer.AllowedIPs,
				}
				if peer.Endpoint != nil {
					devInfo.Peers[peer.PublicKey.String()].Endpoint = peer.Endpoint.String()
				}
			}
		},
		func(env napi.Env, status napi.Status) {
			defer napi.DeleteAsyncWork(env, worker)
			if status == napi.StatusCancelled {
				return
			} else if err != nil {
				v, _ := napi.CreateError(env, nil, js.AsEnv(env).ValueOf(err.Error()).Value)
				napi.RejectDeferred(env, promise.Deferred, v)
				return
			}
			napi.ResolveDeferred(env, promise.Deferred, devInfo.ToNapi(env))
		},
	)
	napi.QueueAsyncWork(env, worker)
	return promise.Value
}

func SetInterface(env napi.Env, info napi.CallbackInfo) napi.Value {
	devInfo := &Config{}
	err := devInfo.FromNapi(env, info)

	result, _ := napi.CreatePromise(env)
	asyncResourceName, _ := napi.CreateStringUtf8(env, "addon/SetInterface")

	var asyncWork napi.AsyncWork
	asyncWork, _ = napi.CreateAsyncWork(env, nil, asyncResourceName,
		func(env napi.Env) {
			if err != nil {
				return
			}

			// Get client to wireguard
			var client *wgctrl.Client
			if client, err = wgctrl.New(); err != nil {
				return
			}
			defer client.Close()
			var devConfig wgtypes.Config
			if devConfig, err = devInfo.WgConfig(); err == nil {
				err = client.ConfigureDevice(devInfo.Name, devConfig)
			}
		},
		func(env napi.Env, status napi.Status) {
			defer napi.DeleteAsyncWork(env, asyncWork)
			if status == napi.StatusCancelled {
				return
			} else if err != nil {
				v, _ := napi.CreateError(env, nil, js.AsEnv(env).ValueOf(err.Error()).Value)
				napi.RejectDeferred(env, result.Deferred, v)
				return
			}
			napi.ResolveDeferred(env, result.Deferred, devInfo.ToNapi(env))
			napi.ResolveDeferred(env, result.Deferred, js.AsEnv(env).Undefined().Value)
		},
	)
	napi.QueueAsyncWork(env, asyncWork)
	return result.Value
}
