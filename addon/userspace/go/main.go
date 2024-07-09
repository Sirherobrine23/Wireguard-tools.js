package main

import "C"

import (
	"fmt"
	"runtime/debug"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {}

// Default log level to print in terminal
const levelLog = device.LogLevelSilent

func getCharErr(err error) *C.char {
	if err == nil {
		return C.CString("")
	}
	return C.CString(err.Error())
}

// Get wireguard-go version
//
//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

// End process function callbacks
var Tuns = make(map[string]tun.Device)
var Devices = make(map[string]*device.Device)

// List wireguard-go UAPI's sockets
// first\0second\0third\0forth\0last\0\0
//
//export listInternalTuns
func listInternalTuns() *C.char {
	var uapis []string
	for tun := range Tuns {
		uapis = append(uapis, tun)
	}
	return C.CString(strings.Join(uapis, "\x00") + "\x00")
}

// Delete interface
//
//export stopWg
func stopWg(wgName *C.char) (bool, *C.char) {
	tunName := C.GoString(wgName)
	if dev, ok := Devices[tunName]; ok {
		dev.Close()
		if tun, ok := Tuns[tunName]; ok {
			if err := tun.Close(); err != nil {
				return false, getCharErr(err)
			}
		}
		return true, nil
	}
	return false, nil
}

// Set config in tun, if not exist create and add to Tuns
//
//export setWg
func setWg(wgName, wgConfig *C.char) *C.char {
	tunName, configString := C.GoString(wgName), C.GoString(wgConfig)
	_, okTuns := Tuns[tunName]
	_, okDev := Devices[tunName]
	if !(okTuns || okDev) {
		logger := device.NewLogger(levelLog, fmt.Sprintf("(%s) ", tunName))
		// open TUN device (or use supplied fd)
		tdev, err := tun.CreateTUN(tunName, device.DefaultMTU)
		Tuns[tunName] = tdev
		if err != nil {
			return getCharErr(err)
		}
		Devices[tunName] = device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	}
	dev := Devices[tunName]
	return getCharErr(dev.IpcSet(configString))
}

// Get config from Tuns device
//
//export getWg
func getWg(wgName *C.char) (*C.char, *C.char) {
	tunName := C.GoString(wgName)
	if dev, ok := Devices[tunName]; ok {
		config, err := dev.IpcGet()
		return C.CString(config), getCharErr(err)
	}
	return nil, getCharErr(fmt.Errorf("device not exists"))
}
