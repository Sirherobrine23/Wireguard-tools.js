package wg_addon

import (
	"fmt"
	"time"

	_ "unsafe"

	_ "sirherobrine23.com.br/Sirherobrine23/napi-go/module"

	"sirherobrine23.com.br/Sirherobrine23/napi-go"
)

//go:linkname wg sirherobrine23.com.br/Sirherobrine23/napi-go/module.Register
func wg(env napi.EnvType, export *napi.Object) {
	constants, err := napi.CreateObject(env)
	if err != nil {
		panic(err)
	}

	setConfig, err := napi.CreateFunction(env, "setConfig", func(ci *napi.CallbackInfo) (napi.ValueType, error) {
		var err error
		if len(ci.Args) < 1 {
			return nil, fmt.Errorf("require only config to set interface")
		}

		if typeof, err := ci.Args[0].Type(); err != nil || typeof.String() != "object" {
			return nil, fmt.Errorf("require only config to set interface")
		}

		var configInput Config
		if err = napi.ValueFrom(ci.Args[0], &configInput); err != nil {
			return nil, err
		}

		return napi.CreateAsyncWorker(env, func(env napi.EnvType) {
			err = createInterface(configInput)
		}, func(env napi.EnvType, Resolve, Reject func(value napi.ValueType)) {
			if err != nil {
				if v, err := napi.CreateError(env, err.Error()); err != nil {
					Reject(v)
					return
				}
			}
			Resolve(nil)
		})
	})
	if err != nil {
		panic(err)
	}

	getConfig, err := napi.CreateFunction(env, "getConfig", func(ci *napi.CallbackInfo) (napi.ValueType, error) {
		if len(ci.Args) < 1 {
			return nil, fmt.Errorf("require interface name to get config")
		}

		t, _ := ci.Args[0].Type()
		if t.String() != "string" {
			return nil, fmt.Errorf("require interface name to get config")
		}

		config := Config{}
		name, _ := napi.ToString(ci.Args[0]).Utf8Value()

		var err error
		return napi.CreateAsyncWorker(env, func(env napi.EnvType) {
			err = getInterface(name, &config)
		}, func(env napi.EnvType, Resolve, Reject func(value napi.ValueType)) {
			if err != nil {
				if v, err := napi.CreateError(env, err.Error()); err != nil {
					Reject(v)
					return
				}
			}

			napiConfig, err := napi.ValueOf(env, config)
			if err != nil {
				if v, err := napi.CreateError(env, err.Error()); err != nil {
					Reject(v)
					return
				}
			}
			Resolve(napiConfig)
		})
	})
	if err != nil {
		panic(err)
	}

	deleteInterface, err := napi.CreateFunction(env, "deleteInterface", func(ci *napi.CallbackInfo) (napi.ValueType, error) {
		if len(ci.Args) < 1 {
			return nil, fmt.Errorf("require interface name to get config")
		}

		t, _ := ci.Args[0].Type()
		if t.String() != "string" {
			return nil, fmt.Errorf("require interface name to get config")
		}

		name, err := napi.ToString(ci.Args[0]).Utf8Value()
		if err != nil {
			return nil, err
		}

		return napi.CreateAsyncWorker(env, func(env napi.EnvType) {
			err = deleteInterface(name)
		}, func(env napi.EnvType, Resolve, Reject func(value napi.ValueType)) {
			if err != nil {
				if v, err := napi.CreateError(env, err.Error()); err != nil {
					Reject(v)
					return
				}
			}
			Resolve(nil)
		})
	})
	if err != nil {
		panic(err)
	}

	if ver, err := wgVersion(); err == nil && ver != "" {
		if ver2, err := napi.CreateString(env, ver); err == nil {
			constants.Set("driveVersion", ver2)
		}
	}

	export.Set("constants", constants)
	export.Set("deleteInterface", deleteInterface)
	export.Set("setConfig", setConfig)
	export.Set("getConfig", getConfig)
}

// Peer info
type Peer struct {
	AllowedIPs    []string  `napi:"allowedIPs"`
	Endpoint      string    `napi:"endpoint"`
	KeepInterval  int       `napi:"keepInterval"`
	PresharedKey  string    `napi:"presharedKey"`
	RemoveMe      bool      `napi:"removeMe"`
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
	Address      []string         `napi:"address"`
	Peers        map[string]*Peer `napi:"peers"`
}
