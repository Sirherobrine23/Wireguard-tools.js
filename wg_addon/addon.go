package wg_addon

import (
	"net"
	"net/netip"
	"time"
	_ "unsafe"

	"sirherobrine23.com.br/Sirherobrine23/napi-go"
	_ "sirherobrine23.com.br/Sirherobrine23/napi-go/entry"
)

//go:linkname wg sirherobrine23.com.br/Sirherobrine23/napi-go/entry.Register
func wg(env napi.EnvType, export *napi.Object) {
	getConfig, err := napi.GoFuncOf(env, GetInterface)
	if err != nil {
		panic(err)
	}
	export.Set("getConfig", getConfig)
	
	setConfig, err := napi.GoFuncOf(env, SetInterface)
	if err != nil {
		panic(err)
	}
	export.Set("setConfig", setConfig)
	
	// deleteInterface, _ := napi.CreateFunction(env, "deleteInterface", DeleteInterface)
	// export.Set("deleteInterface", deleteInterface)
}

// Peer info
type Peer struct {
	PresharedKey string      `napi:"presharedKey"`
	KeepInterval int         `napi:"keepInterval"`
	Endpoint     string      `napi:"endpoint"`
	AllowedIPs   []net.IPNet `napi:"allowedIPs"`

	RemoveMe bool `napi:"removeMe"`

	RxByte        int       `napi:"rxBytes"`
	TxByte        int       `napi:"txBytes"`
	LastHandshake time.Time `napi:"lastHandshake"`
}

// Wireguard interface configs
type Config struct {
	Name         string           `napi:"name"`
	PrivateKey   string           `napi:"privateKey"`
	PublicKey    string           `napi:"publicKey"`
	PortListen   int              `napi:"portListen"`
	Fwmark       int              `napi:"fwmark"`
	ReplacePeers bool             `napi:"replacePeers"`
	Address      []netip.Addr     `napi:"address"`
	Peers        map[string]*Peer `napi:"peers"`
}
