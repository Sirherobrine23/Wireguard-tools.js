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
#include <cstdlib>
#include <win/ipc.cpp>
#include <win/set_ip.cpp>
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

std::string getErrorString(DWORD errorMessageID) {
  if(errorMessageID == 0) ((std::string)"Error code: ").append(std::to_string(errorMessageID));
  LPSTR messageBuffer = nullptr;
  //Ask Win32 to give us the string version of that message ID.
  //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
  size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
  //Copy the error message into a std::string.
  std::string message(messageBuffer, size);
  //Free the Win32's string's buffer.
  LocalFree(messageBuffer);
  return message;
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
  if (!(InitializeWireGuardNT(toLpcwstr(DLLPATH.ToString())))) err = ((std::string)"Failed to initialize WireGuardNT, ").append(getErrorString(GetLastError()));
  return err;
}

std::string versionDrive() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"getWgVersion", L"Wireguard-tools.js", NULL);
  DWORD Version = WireGuardGetRunningDriverVersion();
  if (Version == 0) {
    auto statusErr = GetLastError();
    WireGuardCloseAdapter(Adapter);
    if (statusErr == ERROR_FILE_NOT_FOUND) return "Driver not loaded";
    return ((std::string)"Cannot get version drive, ").append(getErrorString(GetLastError()));
  }
  WireGuardCloseAdapter(Adapter);
  return ((std::string)"WireGuardNT v").append(std::to_string((Version >> 16) & 0xff)).append(".").append(std::to_string((Version >> 0) & 0xff));
}

// Wireguard interfaces
std::vector<std::string> WgInterfaces;

static int decodeBase64(const char src[4]) {
  int val = 0;
  unsigned int i;

  for (i = 0; i < 4; ++i) val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)) << (18 - 6 * i);
  return val;
}

void insertKey(BYTE key[32], std::string keyBase64) {
  auto base64 = keyBase64.c_str();
  if (keyBase64.length() != WG_KEY_LENGTH || base64[WG_KEY_LENGTH - 1] != '=') throw std::string("invalid key, length: ").append(std::to_string(keyBase64.length()));

  unsigned int i;
  int val;
  volatile uint8_t ret = 0;

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
  int status = EINVAL & ~((ret - 1) >> 8);
  if (status != 0) throw std::string("Cannot decode key, ret code: ").append(std::to_string(status));
}

struct SetConfigStruct {
  WIREGUARD_INTERFACE Interface;
  WIREGUARD_PEER Peer;
  WIREGUARD_ALLOWED_IP AllV4;
};

void setConfig::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) {
    Adapter = WireGuardCreateAdapter(toLpcwstr(wgName), L"Wireguard-tools.js", NULL);
    if (!Adapter) return SetError(((std::string)"Failed to create adapter, ").append(getErrorString(GetLastError())));
  }
  bool insertInVector = true;
  for (auto internals : WgInterfaces) if (wgName == internals) { insertInVector = false; break; }
  if (insertInVector) WgInterfaces.push_back(wgName);
  HANDLE handle = kernel_interface_handle(wgName.c_str());
  if (!handle) return SetError("Cannot get Adapter handler");

  WG_IOCTL_INTERFACE *wg_iface = NULL;
  WG_IOCTL_PEER *wg_peer;
  WG_IOCTL_ALLOWED_IP *wg_aip;
  DWORD buf_len = sizeof(WG_IOCTL_INTERFACE);
  struct wgpeer *peer;
  struct wgallowedip *aip;
  size_t peer_count, aip_count;
  int ret = 0;
  for (auto peer : peersVector) {
    if (DWORD_MAX - buf_len < sizeof(WG_IOCTL_PEER)) {
      errno = EOVERFLOW;
      goto out;
    }
    buf_len += sizeof(WG_IOCTL_PEER);
    for (auto aip : peer.second.allowedIPs) {
      if (DWORD_MAX - buf_len < sizeof(WG_IOCTL_ALLOWED_IP)) {
        errno = EOVERFLOW;
        goto out;
      }
      buf_len += sizeof(WG_IOCTL_ALLOWED_IP);
    }
  }
  wg_iface = (WG_IOCTL_INTERFACE *)calloc(1, buf_len);
  if (!wg_iface) goto out;

  if (privateKey.size() == WG_KEY_LENGTH) {
    try {
      insertKey(wg_iface->PrivateKey, privateKey);
      wg_iface->Flags = (WG_IOCTL_INTERFACE_FLAG)(wg_iface->Flags|WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY);
    } catch (std::string &err) {
      return SetError(((std::string)"Invalid privateKey, ").append(err));
    }
  }

  if (portListen >= 0) {
    wg_iface->ListenPort = portListen;
    wg_iface->Flags = (WG_IOCTL_INTERFACE_FLAG)(wg_iface->Flags|WG_IOCTL_INTERFACE_HAS_LISTEN_PORT);
  }

  if (replacePeers) wg_iface->Flags = (WG_IOCTL_INTERFACE_FLAG)(wg_iface->Flags|WG_IOCTL_INTERFACE_FLAG::WG_IOCTL_INTERFACE_REPLACE_PEERS);
  peer_count = 0;
  wg_peer = (WG_IOCTL_PEER*)((WG_IOCTL_PEER*)wg_iface + sizeof(WG_IOCTL_INTERFACE));
  for (auto peer : peersVector) {
    try {
      insertKey(wg_peer->PublicKey, peer.first);
      wg_peer->Flags = WG_IOCTL_PEER_HAS_PUBLIC_KEY;
    } catch (std::string &err) {
      return SetError(((std::string)"Invalid peer publicKey, ").append(err));
    }

    if (peer.second.removeMe) wg_peer->Flags = (WG_IOCTL_PEER_FLAG)(wg_peer->Flags|WG_IOCTL_PEER_FLAG::WG_IOCTL_PEER_REMOVE);
    else {
      if (peer.second.presharedKey.size() == WG_KEY_LENGTH) {
        try {
          insertKey(wg_peer->PresharedKey, peer.second.presharedKey);
          wg_peer->Flags = (WG_IOCTL_PEER_FLAG)(wg_peer->Flags|WG_IOCTL_PEER_FLAG::WG_IOCTL_PEER_HAS_PRESHARED_KEY);
        } catch (std::string &err) {
          return SetError(((std::string)"Invalid peer presharedKey, ").append(err));
        }
      }
      if (peer.second.keepInterval >= 0) {
        wg_peer->PersistentKeepalive = peer.second.keepInterval;
        wg_peer->Flags = (WG_IOCTL_PEER_FLAG)(wg_peer->Flags|WG_IOCTL_PEER_FLAG::WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE);
      }

      if (peer.second.endpoint.size() > 0) parseEndpoint(&wg_peer->Endpoint, peer.second.endpoint.c_str());

      aip_count = 0;
      wg_aip = (WG_IOCTL_ALLOWED_IP*)wg_peer + sizeof(WG_IOCTL_PEER);
      for (auto aip : peer.second.allowedIPs) {
        if (strchr(aip.c_str(), ':')) {
          if (inet_pton(AF_INET6, aip.c_str(), &wg_aip->Address.V4) == 1) {
            wg_aip->AddressFamily = AF_INET6;
            wg_aip->Cidr = 32;
          } else continue;
        } else {
          if (inet_pton(AF_INET, aip.c_str(), &wg_aip->Address.V6) == 1) {
            wg_aip->AddressFamily = AF_INET;
            wg_aip->Cidr = 128;
          } else continue;
        }
        ++aip_count;
        ++wg_aip;
      }
      wg_peer->AllowedIPsCount = aip_count;
      ++peer_count;
		  wg_peer = (WG_IOCTL_PEER *)wg_aip;
    }
  }
  wg_iface->PeersCount = peer_count;

  if (!DeviceIoControl(handle, WG_IOCTL_SET, NULL, 0, (void *)wg_iface, buf_len, &buf_len, NULL)) {
    SetError(((std::string)"Failed to set interface config, ").append(getErrorString(GetLastError())));
    goto out;
  }
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP))) {
    return SetError(((std::string)"Failed to set Up interface, ").append(getErrorString(GetLastError())));
    goto out;
  }
	errno = 0;

  out:
  ret = -errno;
  free(wg_iface);
  if (errno != 0) {
    if (errno == EACCES) return SetError(((std::string)"Cannot set config"));
    SetError(((std::string)"OUT: Handler code exit: ").append(std::to_string(-errno)));
  }
}

void getConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void deleteInterface::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) return SetError("This interface not exists in Wireguard-Tools.js addon!");
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN))) return SetError(((std::string)"Failed to set down interface, ").append(getErrorString(GetLastError())));
  WireGuardCloseAdapter(Adapter);
  for (auto it = WgInterfaces.begin(); it != WgInterfaces.end(); ++it) if (wgName == (*it)) WgInterfaces.erase(it);
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

  for (auto internals : WgInterfaces) deviceNames.push_back(internals);
  for (auto internals : kernel_get_wireguard_interfaces()) deviceNames.push_back(internals);
}
