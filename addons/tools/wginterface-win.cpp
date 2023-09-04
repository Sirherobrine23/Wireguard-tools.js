#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include "wireguard.h"
#include <windows.h>
#include <tlhelp32.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sysinfoapi.h>
#include <winternl.h>
#include "wginterface.hh"

#define IFNAMSIZ MAX_ADAPTER_NAME - 1

static WIREGUARD_CREATE_ADAPTER_FUNC *WireGuardCreateAdapter;
static WIREGUARD_OPEN_ADAPTER_FUNC *WireGuardOpenAdapter;
static WIREGUARD_CLOSE_ADAPTER_FUNC *WireGuardCloseAdapter;
static WIREGUARD_GET_ADAPTER_LUID_FUNC *WireGuardGetAdapterLUID;
static WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *WireGuardGetRunningDriverVersion;
static WIREGUARD_DELETE_DRIVER_FUNC *WireGuardDeleteDriver;
static WIREGUARD_SET_LOGGER_FUNC *WireGuardSetLogger;
static WIREGUARD_SET_ADAPTER_LOGGING_FUNC *WireGuardSetAdapterLogging;
static WIREGUARD_GET_ADAPTER_STATE_FUNC *WireGuardGetAdapterState;
static WIREGUARD_SET_ADAPTER_STATE_FUNC *WireGuardSetAdapterState;
static WIREGUARD_GET_CONFIGURATION_FUNC *WireGuardGetConfiguration;
static WIREGUARD_SET_CONFIGURATION_FUNC *WireGuardSetConfiguration;

unsigned long maxName() {
  return IFNAMSIZ;
}

HMODULE InitializeWireGuardNT(LPCWSTR dllPath = L"wireguard.dll") {
  HMODULE WireGuardDll = LoadLibraryExW(dllPath, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!WireGuardDll) return NULL;
  #define X(Name) ((*(FARPROC *)&Name = GetProcAddress(WireGuardDll, #Name)) == NULL)
  if (X(WireGuardCreateAdapter) || X(WireGuardOpenAdapter) || X(WireGuardCloseAdapter) ||
    X(WireGuardGetAdapterLUID) || X(WireGuardGetRunningDriverVersion) || X(WireGuardDeleteDriver) ||
    X(WireGuardSetLogger) || X(WireGuardSetAdapterLogging) || X(WireGuardGetAdapterState) ||
    X(WireGuardSetAdapterState) || X(WireGuardGetConfiguration) || X(WireGuardSetConfiguration))
  #undef X
  {
    DWORD LastError = GetLastError();
    FreeLibrary(WireGuardDll);
    SetLastError(LastError);
    return NULL;
  }
  return WireGuardDll;
}

LPCWSTR toLpcwstr(std::string s) {
  wchar_t* wString = new wchar_t[s.length()+1];
  MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, wString, s.length()+1);
  return wString;
}

std::string startAddon(const Napi::Env env) {
  std::string err = "";
  auto DLLPATH = env.Global().ToObject().Get("WIREGUARD_DLL_PATH");
  if (!(DLLPATH.IsString())) return "Require WIREGUARD_DLL_PATH in Global process";
  if (!(InitializeWireGuardNT(toLpcwstr(DLLPATH.ToString())))) err = ((std::string)"Failed to initialize WireGuardNT, error code: ").append(std::to_string(GetLastError()));
  return err;
}

std::string versionDrive() {
  GUID ExampleGuid;
  CoCreateGuid(&ExampleGuid);
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"getWgVersion", L"Wireguard-tools.js", &ExampleGuid);
  DWORD Version = WireGuardGetRunningDriverVersion();
  if (Version == 0) {
    auto statusErr = GetLastError();
    WireGuardCloseAdapter(Adapter);
    if (statusErr == ERROR_FILE_NOT_FOUND) return "Driver not loaded";
    return ((std::string)"Cannot get version drive, error code: ").append(std::to_string(GetLastError()));
  }
  WireGuardCloseAdapter(Adapter);
  return ((std::string)"WireGuardNT v").append(std::to_string((Version >> 16) & 0xff)).append(".").append(std::to_string((Version >> 0) & 0xff));
}

// Wireguard interfaces
std::map<std::string, WIREGUARD_ADAPTER_HANDLE> WgInterfaces;

static int decodeBase64(const char src[4]) {
  int val = 0;
  unsigned int i;

  for (i = 0; i < 4; ++i) val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)) << (18 - 6 * i);
  return val;
}

int insertKey(BYTE *key, std::string keyBase64) {
  auto base64 = keyBase64.c_str();
  unsigned int i;
  int val;
  volatile uint8_t ret = 0;

  if (keyBase64.length() != WIREGUARD_KEY_LENGTH - 1 || base64[WIREGUARD_KEY_LENGTH - 2] != '=') {
    errno = EINVAL;
    return -errno;
  }

  for (i = 0; i < 32 / 3; ++i) {
    val = decodeBase64(&base64[i * 4]);
    ret |= (uint32_t)val >> 31;
    key[i * 3 + 0] = (val >> 16) & 0xff;
    key[i * 3 + 1] = (val >> 8) & 0xff;
    key[i * 3 + 2] = val & 0xff;
  }
  const char tempDecode[4] = {base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A'};
  val = decodeBase64(tempDecode);
  ret |= ((uint32_t)val >> 31) | (val & 0xff);
  key[i * 3 + 0] = (val >> 16) & 0xff;
  key[i * 3 + 1] = (val >> 8) & 0xff;
  errno = EINVAL & ~((ret - 1) >> 8);
  return -errno;
}

std::string createWgInterface(std::string name) {
  std::string err = "";
  for (auto internals : WgInterfaces) if (name == internals.first) return err;
  GUID wgGuid;
  CoCreateGuid(&wgGuid);
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(toLpcwstr(name), L"Wireguard-tools.js", &wgGuid);
  if (!Adapter) err = ((std::string)"Failed to create adapter, error code: ").append(std::to_string(GetLastError()));
  return err;
}

void setConfig::Execute() {
  auto createStatus = createWgInterface(wgName);
  if (createStatus.length() >= 1) return SetError(createStatus);
  WIREGUARD_ADAPTER_HANDLE Adapter = WgInterfaces[wgName];
  auto interfaceConfig = new WIREGUARD_INTERFACE({});

  // Private key
  interfaceConfig->Flags = WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;
  insertKey(interfaceConfig->PrivateKey, privateKey);

  // Public key
  if (publicKey.size() == WIREGUARD_KEY_LENGTH) {
    interfaceConfig->Flags = (WIREGUARD_INTERFACE_FLAG)(interfaceConfig->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PUBLIC_KEY);
    insertKey(interfaceConfig->PublicKey, publicKey);
  }

  // Port listen
  if (portListen >= 0) {
    interfaceConfig->Flags = (WIREGUARD_INTERFACE_FLAG)(interfaceConfig->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
    interfaceConfig->ListenPort = portListen;
  }

  // if (replacePeers) interfaceConfig->Flags = (WIREGUARD_INTERFACE_FLAG)(interfaceConfig->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_REPLACE_PEERS);
  // interfaceConfig->PeersCount = peersVector.size();
  // for (auto &peer : peersVector) {
  //   WIREGUARD_PEER peerSetts;
  //   peerSetts.Flags = WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PUBLIC_KEY;
  //   insertKey(peerSetts.PublicKey, peer.first);

  //   if (peer.second.removeMe) peerSetts.Flags = (WIREGUARD_PEER_FLAG)(peerSetts.Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REMOVE);
  //   else {
  //     peerSetts.Flags = (WIREGUARD_PEER_FLAG)(peerSetts.Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_UPDATE);
  //     if (peer.second.presharedKey.size() == WIREGUARD_KEY_LENGTH) {
  //       peerSetts.Flags = (WIREGUARD_PEER_FLAG)(peerSetts.Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY);
  //       insertKey(peerSetts.PresharedKey, peer.second.presharedKey);
  //     }
  //   }
  // }

  std::cout << "Deploy config" << std::endl;
  if (!(WireGuardSetConfiguration(Adapter, interfaceConfig, sizeof(interfaceConfig)))) return SetError(((std::string)"Failed to set configuration, Error code: ").append(std::to_string(GetLastError())));
}

void getConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void deleteInterface::Execute() {
  for (auto internals : WgInterfaces) {
    if (wgName == internals.first) {
      WireGuardCloseAdapter(internals.second);
      return;
    }
  }
  SetError("This interface not exists in Wireguard-Tools.js addon!");
}

void listDevices::Execute() {
  std::vector<std::string> arrayPrefix;
  arrayPrefix.push_back("ProtectedPrefix\\Administrators\\WireGuard\\");
  arrayPrefix.push_back("WireGuard\\");

  WIN32_FIND_DATA find_data;
  HANDLE find_handle;
  int ret = 0;
  for (auto & preit : arrayPrefix) {
    ret = 0;
    find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return SetError("Invalid Handler");

    char *iface;
    do {
      if (strncmp(preit.c_str(), find_data.cFileName, strlen(preit.c_str()))) continue;
      iface = find_data.cFileName + strlen(preit.c_str());
      deviceNames.push_back(iface);
    } while (FindNextFile(find_handle, &find_data));
    FindClose(find_handle);
    if (ret < 0) {
      std::string err = "Erro code: ";
      err = err.append(std::to_string(ret));
      return SetError(err);
    }
  }

  for (auto internals : WgInterfaces) deviceNames.push_back(internals.first);
}
