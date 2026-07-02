//go:build android || linux || windows

package wg_addon

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func wgVersion() (_ string, _ error) { return }

func deleteInterface(name string) error {
	return fmt.Errorf("not supported now")
}

func createInterface(config Config) error {
	// Get client to wireguard
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	c, err := config.wgConfig()
	if err != nil {
		return err
	}

	return client.ConfigureDevice(config.Name, c)
}

func getInterface(name string, config *Config) error {
	// Get client to wireguard
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	wgConfig, err := client.Device(name)
	if err != nil {
		return err
	}

	config.fromWg(wgConfig)
	return nil
}

func (cfg Config) wgConfig() (wgtypes.Config, error) {
	config := wgtypes.Config{
		ListenPort:   new(cfg.PortListen),
		FirewallMark: new(cfg.Fwmark),
		ReplacePeers: cfg.ReplacePeers,
		Peers:        []wgtypes.PeerConfig{},
	}
	pk, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return config, err
	}
	config.PrivateKey = new(pk)

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
			peer := wgtypes.PeerConfig{PublicKey: pb}

			for _, addr := range peerInfo.AllowedIPs {
				if _, a, err := net.ParseCIDR(addr); err == nil {
					peer.AllowedIPs = append(peer.AllowedIPs, *a)
				}
			}

			if peerInfo.PresharedKey != "" {
				pr, err := wgtypes.ParseKey(peerInfo.PresharedKey)
				if err != nil {
					return config, err
				}
				peer.PresharedKey = new(pr)
			}

			if peerInfo.Endpoint != "" {
				if peer.Endpoint, err = net.ResolveUDPAddr("udp", peerInfo.Endpoint); err != nil {
					return config, err
				}
			}

			peer.PersistentKeepaliveInterval = new(time.Duration(peerInfo.KeepInterval))

			// Append to config
			config.Peers = append(config.Peers, peer)
		}
	}

	return config, nil
}

func (cfg *Config) fromWg(dev *wgtypes.Device) {
	*cfg = Config{}

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
			AllowedIPs:    []string{},
		}
		for _, p := range peer.AllowedIPs {
			cfg.Peers[peer.PublicKey.String()].AllowedIPs = append(cfg.Peers[peer.PublicKey.String()].AllowedIPs, p.String())
		}
		if peer.Endpoint != nil {
			cfg.Peers[peer.PublicKey.String()].Endpoint = peer.Endpoint.String()
		}
	}
}
