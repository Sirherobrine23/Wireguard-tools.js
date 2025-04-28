//go:build linux || windows

package wg_addon

import (
	"context"
	"fmt"
	"net"
	"time"

	"sirherobrine23.com.br/Sirherobrine23/napi-go"
	"sirherobrine23.com.br/Sirherobrine23/napi-go/js"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var SetInterface = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("set interface config")
	}

	var wgDevConfig Config
	if err := js.ValueFrom(args[0], &wgDevConfig); err != nil {
		return nil, err
	}

	promise, err := napi.CreatePromise(env)
	if err != nil {
		return nil, err
	}
	_, err = napi.CreateAyncWorker(env, context.Background(), func(env napi.EnvType, ctx context.Context) {
		devInfo, err := wgDevConfig.WgConfig()
		if err != nil {
			napiErr, _ := napi.CreateError(env, err.Error())
			promise.Reject(napiErr)
			return
		}

		// Get client to wireguard
		client, err := wgctrl.New()
		if err != nil {
			napiErr, _ := napi.CreateError(env, err.Error())
			promise.Reject(napiErr)
			return
		}
		defer client.Close()

		// Set Config
		if err := client.ConfigureDevice(wgDevConfig.Name, devInfo); err != nil {
			napiErr, _ := napi.CreateError(env, err.Error())
			promise.Reject(napiErr)
			return
		}

		// Resolve promise
		und, _ := env.Undefined()
		promise.Resolve(und)
	})
	return promise, err
})

var GetInterface = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("set interface name")
	}
	interfaceName := napi.ToString(args[0])
	typeof, err := interfaceName.Type()
	if !(err == nil || typeof == napi.TypeString) {
		return nil, fmt.Errorf("set interface name")
	}

	var config Config

	{
		interfaceName, _ := interfaceName.Utf8Value()
		// Get client to wireguard
		var client *wgctrl.Client
		if client, err = wgctrl.New(); err != nil {
			return nil, err
		}
		defer client.Close()

		// Get config
		var dev *wgtypes.Device
		if dev, err = client.Device(interfaceName); err != nil {
			return nil, err
		}
		config.FromWg(dev)
	}

	return js.ValueOf(env, config)
})

var DeleteInterface = napi.Callback(func(env napi.EnvType, this napi.ValueType, args []napi.ValueType) (napi.ValueType, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("set interface name")
	}
	interfaceName := napi.ToString(args[0])
	typeof, err := interfaceName.Type()
	if !(err == nil || typeof == napi.TypeString) {
		return nil, fmt.Errorf("set interface name")
	}

	{
		// interfaceName, _ := interfaceName.Utf8Value()
		// // Get client to wireguard
		// var client *wgctrl.Client
		// if client, err = wgctrl.New(); err != nil {
		// 	return nil, err
		// }
		// defer client.Close()
	}
	return nil, nil
})

func pointValue[T any](v T) *T { return &v }

func (cfg Config) WgConfig() (wgtypes.Config, error) {
	config := wgtypes.Config{
		ListenPort:   pointValue(cfg.PortListen),
		FirewallMark: pointValue(cfg.Fwmark),
		ReplacePeers: cfg.ReplacePeers,
		Peers:        []wgtypes.PeerConfig{},
	}
	pk, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return config, err
	}
	config.PrivateKey = pointValue(pk)

	for peerKey, peerInfo := range cfg.Peers {
		pb, err := wgtypes.ParseKey(peerKey)
		if err != nil {
			return config, err
		}

		if peerInfo.RemoveMe {
			config.Peers = append(config.Peers, wgtypes.PeerConfig{
				PublicKey: pb,
				Remove:    true,
			})
		} else {
			peer := wgtypes.PeerConfig{PublicKey: pb, AllowedIPs: peerInfo.AllowedIPs}
			if peerInfo.PresharedKey != "" {
				pr, err := wgtypes.ParseKey(peerInfo.PresharedKey)
				if err != nil {
					return config, err
				}
				peer.PresharedKey = pointValue(pr)
			}

			if peerInfo.Endpoint != "" {
				if peer.Endpoint, err = net.ResolveUDPAddr("udp", peerInfo.Endpoint); err != nil {
					return config, err
				}
			}

			peer.PersistentKeepaliveInterval = pointValue(time.Duration(peerInfo.KeepInterval))

			// Append to config
			config.Peers = append(config.Peers, peer)
		}
	}

	return config, nil
}

func (cfg *Config) FromWg(dev *wgtypes.Device) {
	cfg.PublicKey = dev.PublicKey.String()
	cfg.PrivateKey = dev.PrivateKey.String()
	cfg.PortListen = dev.ListenPort
	cfg.Fwmark = dev.FirewallMark
	cfg.Peers = map[string]*Peer{}
	for _, peer := range dev.Peers {
		cfg.Peers[peer.PublicKey.String()] = &Peer{
			PresharedKey:  peer.PresharedKey.String(),
			LastHandshake: peer.LastHandshakeTime,
			KeepInterval:  int(peer.PersistentKeepaliveInterval.Seconds()),
			TxByte:        int(peer.TransmitBytes),
			RxByte:        int(peer.ReceiveBytes),
			AllowedIPs:    peer.AllowedIPs,
		}
		if peer.Endpoint != nil {
			cfg.Peers[peer.PublicKey.String()].Endpoint = peer.Endpoint.String()
		}
	}
}
