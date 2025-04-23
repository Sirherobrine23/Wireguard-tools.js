package addon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/abhisekp/napi-go"
	napiEntry "github.com/abhisekp/napi-go/entry"
	"github.com/abhisekp/napi-go/js"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func init() {
	// napiEntry.Export("constant", func(env napi.Env, info napi.CallbackInfo) napi.Value { return nil })
	// deleteInterface(name: string): Promise<void>;
	// napiEntry.Export("deleteInterface", GetInterface)
	napiEntry.Export("getConfig", GetInterface)
	napiEntry.Export("setConfig", SetInterface)
}

type PkgInfo struct {
	DriveVersion string `json:"driveVersion"`
}

type Peer struct {
	PresharedKey string
	KeepInterval int
	Endpoint     string
	AllowedIPs   []net.IPNet

	RemoveMe      bool
	RxByte        int
	TxByte        int
	LastHandshake time.Time
}

type Config struct {
	Name         string
	PrivateKey   string
	PublicKey    string
	PortListen   int
	Fwmark       int
	ReplacePeers bool
	Address      []netip.Addr
	Peers        map[string]*Peer
}

func mustBigInt(env napi.Env, v int) napi.Value {
	b, _ := napi.CreateBigIntInt64(env, int64(v))
	return b
}

func processArgs(env napi.Env, info napi.CallbackInfo) ([]js.Value, error) {
	cbInfo, st := napi.GetCbInfo(env, info)
	if st != napi.StatusOK {
		return nil, napi.StatusError(st)
	}
	jsEnv := js.AsEnv(env)
	args := make([]js.Value, len(cbInfo.Args))
	for i, cbArg := range cbInfo.Args {
		args[i] = js.Value{
			Env:   jsEnv,
			Value: cbArg,
		}
	}
	return args, nil
}

func (cfg Config) ToNapi(env napi.Env) napi.Value {
	obj := map[string]any{}
	addrs := []string{}
	peers := map[string]map[string]any{}

	for _, addr := range cfg.Address {
		addrs = append(addrs, addr.String())
	}

	for pubKey, peer := range cfg.Peers {
		peerAddr := []string{}
		for _, addr := range peer.AllowedIPs {
			peerAddr = append(peerAddr, addr.String())
		}

		peers[pubKey] = map[string]any{
			"presharedKey":  peer.PresharedKey,
			"keepInterval":  peer.KeepInterval,
			"endpoint":      peer.Endpoint,
			"allowdIPs":     peerAddr,
			"lastHandshake": peer.LastHandshake,
			"rxBytes":       mustBigInt(env, peer.RxByte),
			"txBytes":       mustBigInt(env, peer.TxByte),
		}
	}

	obj["privateKey"] = cfg.PrivateKey
	obj["publicKey"] = cfg.PrivateKey
	obj["portListen"] = cfg.PortListen
	obj["fwmark"] = cfg.Fwmark
	obj["fwmark"] = cfg.Fwmark
	obj["address"] = addrs
	obj["peers"] = peers

	return js.AsEnv(env).ValueOf(obj).Value
}

func mustNapi[T any](v T, _ napi.Status) T {
	return v
}

func (cfg *Config) FromNapi(env napi.Env, info napi.CallbackInfo) error {
	args, err := processArgs(env, info)
	if err != nil {
		return err
	} else if len(args) == 0 {
		return errors.New("return config to Wireguard interface")
	}
	configValue := args[0].Value
	if !mustNapi(napi.HasNamedProperty(env, configValue, "name")) {
		return fmt.Errorf("set wireguard interface name!")
	} else if !mustNapi(napi.HasNamedProperty(env, configValue, "privateKey")) {
		return fmt.Errorf("require privateKey to wireguard interface")
	}

	cfg.Name = mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetNamedProperty(env, configValue, "name"))))
	cfg.PrivateKey = mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetNamedProperty(env, configValue, "privateKey"))))
	if mustNapi(napi.HasNamedProperty(env, configValue, "publicKey")) {
		cfg.PublicKey = mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetNamedProperty(env, configValue, "publicKey"))))
	}
	if mustNapi(napi.HasNamedProperty(env, configValue, "portListen")) {
		cfg.PortListen = int(mustNapi(napi.GetValueInt32(env, mustNapi(napi.GetNamedProperty(env, configValue, "portListen")))))
	}
	if mustNapi(napi.HasNamedProperty(env, configValue, "fwmark")) {
		cfg.Fwmark = int(mustNapi(napi.GetValueInt64(env, mustNapi(napi.GetNamedProperty(env, configValue, "fwmark")))))
	}
	if mustNapi(napi.HasNamedProperty(env, configValue, "replacePeers")) {
		cfg.ReplacePeers = mustNapi(napi.GetValueBool(env, mustNapi(napi.GetNamedProperty(env, configValue, "replacePeers"))))
	}

	if mustNapi(napi.IsArray(env, mustNapi(napi.GetNamedProperty(env, configValue, "address")))) {
		arrayValue := mustNapi(napi.GetNamedProperty(env, configValue, "address"))
		sliceSize := mustNapi(napi.GetArrayLength(env, arrayValue))
		cfg.Address = make([]netip.Addr, sliceSize)
		for index := range sliceSize {
			addrStr := mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetElement(env, arrayValue, index))))
			if cfg.Address[index], err = netip.ParseAddr(addrStr); err != nil {
				return fmt.Errorf("%s: %s", addrStr, err)
			}
		}
	}

	if mustNapi(napi.HasNamedProperty(env, configValue, "peers")) {
		cfg.Peers = map[string]*Peer{}

		peers := mustNapi(napi.GetNamedProperty(env, configValue, "peers"))
		keys := mustNapi(napi.GetPropertyNames(env, peers))
		keysSize := mustNapi(napi.GetArrayLength(env, keys))
		for index := range keysSize {
			publicKey := mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetElement(env, keys, index))))
			peerObj := mustNapi(napi.GetNamedProperty(env, peers, publicKey))

			if mustNapi(napi.HasNamedProperty(env, peerObj, "removeMe")) && mustNapi(napi.GetValueBool(env, mustNapi(napi.GetNamedProperty(env, peers, "removeMe")))) {
				cfg.Peers[publicKey] = &Peer{RemoveMe: true}
			} else {
				peerInfo := &Peer{}
				cfg.Peers[publicKey] = peerInfo

				if mustNapi(napi.HasNamedProperty(env, peerObj, "presharedKey")) {
					peerInfo.PresharedKey = mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetNamedProperty(env, peerObj, "presharedKey"))))
				}
				if mustNapi(napi.HasNamedProperty(env, peerObj, "keepInterval")) {
					peerInfo.KeepInterval = int(mustNapi(napi.GetValueInt32(env, mustNapi(napi.GetNamedProperty(env, peerObj, "keepInterval")))))
				}
				if mustNapi(napi.HasNamedProperty(env, peerObj, "endpoint")) {
					peerInfo.Endpoint = mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetNamedProperty(env, peerObj, "endpoint"))))
				}
				if mustNapi(napi.IsArray(env, mustNapi(napi.GetNamedProperty(env, peerObj, "allowedIPs")))) {
					ips := mustNapi(napi.GetNamedProperty(env, peerObj, "allowedIPs"))
					ipsSize := mustNapi(napi.GetArrayLength(env, ips))
					peerInfo.AllowedIPs = make([]net.IPNet, ipsSize)
					for index := range ipsSize {
						addr := mustNapi(napi.GetValueStringUtf8(env, mustNapi(napi.GetElement(env, ips, index))))
						if _, ip, err := net.ParseCIDR(addr); err == nil {
							peerInfo.AllowedIPs[index] = *ip
						} else {
							ipAddr, err := netip.ParseAddr(addr)
							if err != nil {
								return err
							}
							if ipAddr.Is4() {
								peerInfo.AllowedIPs[index] = net.IPNet{IP: net.ParseIP(addr), Mask: net.CIDRMask(31, 32)}
							} else {
								peerInfo.AllowedIPs[index] = net.IPNet{IP: net.ParseIP(addr), Mask: net.CIDRMask(64, 128)}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

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
