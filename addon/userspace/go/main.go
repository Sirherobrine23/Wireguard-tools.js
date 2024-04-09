package main

import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	_ "unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

)

const levelLog = device.LogLevelError

//go:linkname socketDirectory golang.xz2c4.com/wireguard/ipc.socketDirectory
var socketDirectory = "/var/run/wireguard"

func init() {
	if runtime.GOOS == "windows" {
		socketDirectory = `\\.\pipe\ProtectedPrefix\Administrators\WireGuard`
	}
}

// End process function callbacks
var TunsEndProcess = make(map[string]func())

//export callEndProcess
func callEndProcess() {
	for _, f := range TunsEndProcess {
		f()
	}
}

func main() {}
func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		callEndProcess()
	}()
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

// Check if tunnel exist
//
//export existTun
func existTun(tunName string) bool {
	Files, err := os.ReadDir(socketDirectory)
	if err != nil {
		return false
	}
	for _, file := range Files {
		if file.IsDir() {
			continue
		}
		splits := strings.Split(file.Name(), "/")
		splits[len(splits)-1] = strings.TrimSuffix(splits[len(splits)-1], ".sock")
		if splits[len(splits)-1] == tunName {
			return true
		}
	}
	return false
}

// Delete wireguard tunnel if exist
//
//export deleteTun
func deleteTun(_tunName *C.char) *C.char {
	tunName := C.GoString(_tunName)
	if !existTun(tunName) {
		return C.CString("Tun does not exist")
	}
	Files, err := os.ReadDir(socketDirectory)
	if err != nil {
		return C.CString("Tun does not exist")
	}
	for _, file := range Files {
		if file.IsDir() {
			continue
		}
		splits := strings.Split(file.Name(), "/")
		splits[len(splits)-1] = strings.TrimSuffix(splits[len(splits)-1], ".sock")
		if splits[len(splits)-1] == tunName {
			os.Remove(strings.Join(([]string{socketDirectory, file.Name()}), "/"))
			return C.CString("")
		}
	}
	return C.CString("Tun does not exist")
}

// Create wireguard tunnel
//
//export createTun
func createTun(_tunName *C.char) *C.char {
	interfaceName := C.GoString(_tunName)
	if existTun(interfaceName) {
		errStr := C.GoString(deleteTun(_tunName))
		if errStr != "" {
			return C.CString(errStr)
		}
	}
	logger := device.NewLogger(levelLog, fmt.Sprintf("(%s) ", interfaceName))

	// open TUN device (or use supplied fd)
	tdev, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	if err != nil {
		return C.CString(fmt.Sprintf("Failed to create TUN device: %v", err))
	}

	// open UAPI file (or use supplied fd)
	fileUAPI, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		tdev.Close()
		return C.CString(fmt.Sprintf("Failed to open UAPI file: %v", err))
	}

	// create device
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		dev.Close()
		tdev.Close()
		return C.CString(fmt.Sprintf("Failed to listen on UAPI file: %v", err))
	}

	// UAPI Listener
	uapiListened := uapi.Addr().String()

	clean := func() {
		logger.Verbosef("Shutting down")

		uapi.Close()
		dev.Close()
		tdev.Close()
		if uapiListened[:1] == "/" {
			os.Remove(uapiListened)
		}
		delete(TunsEndProcess, uapiListened)
	}

	TunsEndProcess[uapiListened] = clean

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				logger.Verbosef("UAPI listener closed")
				clean()
				break
			}
			logger.Verbosef("UAPI recive message")
			go dev.IpcHandle(conn)
		}
	}()

	go func() {
		logger.Verbosef("Device started")
		<-dev.Wait()
		logger.Verbosef("Device closing")
		clean()
	}()

	// Wait for device listener socket to be ready
	for {
		_, err := os.Stat(uapiListened)
		if err == nil {
			break
		}
	}
	return C.CString("")
}

// List wireguard-go UAPI's sockets
// first\0second\0third\0forth\0last\0\0
//
//export listUapis
func listUapis() *C.char {
	Files, err := os.ReadDir(socketDirectory)
	if err != nil {
		return C.CString("")
	}
	var uapis []string
	for _, file := range Files {
		if file.IsDir() {
			continue
		}
		uapis = append(uapis, strings.Join(([]string{socketDirectory, file.Name()}), "/"))
	}
	return C.CString(strings.Join(uapis, "\x00") + "\x00")
}
