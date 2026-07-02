//go:build !(android || linux || windows)

package wg_addon

import (
	"fmt"
)

func wgVersion() (_ string, _ error) { return }

func deleteInterface(name string) error {
	return fmt.Errorf("not supported now")
}

func createInterface(config Config) error {
	return nil
}

func getInterface(name string, config *Config) error {
	return nil
}
