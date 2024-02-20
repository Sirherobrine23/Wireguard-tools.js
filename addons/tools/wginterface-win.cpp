#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <wireguard-nt/include/wireguard.h>
#include <win/shared.cpp>
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
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include "wginterface.hh"
#include <wgkeys.hh>

const DEVPROPKEY devpkey_name = { { 0x65726957, 0x7547, 0x7261, { 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x4b, 0x65, 0x79 } }, DEVPROPID_FIRST_USABLE + 1 };
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
  if (errorMessageID == 0 || errorMessageID < 0) std::string("Error code: ").append(std::to_string(errorMessageID));
  LPSTR messageBuffer = nullptr;
  //Ask Win32 to give us the string version of that message ID.
  //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
  size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
  //Copy the error message into a std::string.
  std::string message(messageBuffer, size);
  //Free the Win32's string's buffer.
  LocalFree(messageBuffer);
  return std::string("Error code: ").append(std::to_string(errorMessageID)).append(", Message: ").append(message);
}

std::string startAddon(const Napi::Env env, Napi::Object exports) {
  if (!IsRunAsAdmin()) return "Run nodejs with administrator privilegies";
  auto DLLPATH = exports.Get("WIN32DLLPATH");
  if (!(DLLPATH.IsString())) return "Require WIREGUARD_DLL_PATH in addon load!";
  LPCWSTR dllPath = toLpcwstr(DLLPATH.ToString());

  HMODULE WireGuardDll = LoadLibraryExW(dllPath, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!WireGuardDll) return std::string("Failed to initialize WireGuardNT, ").append(getErrorString(GetLastError()));;
  #define X(Name) ((*(FARPROC *)&Name = GetProcAddress(WireGuardDll, #Name)) == NULL)
  if (X(WireGuardCreateAdapter) || X(WireGuardOpenAdapter) || X(WireGuardCloseAdapter) || X(WireGuardGetAdapterLUID) || X(WireGuardGetRunningDriverVersion) || X(WireGuardDeleteDriver) || X(WireGuardSetLogger) || X(WireGuardSetAdapterLogging) || X(WireGuardGetAdapterState) || X(WireGuardSetAdapterState) || X(WireGuardGetConfiguration) || X(WireGuardSetConfiguration))
  #undef X
  {
    DWORD LastError = GetLastError();
    FreeLibrary(WireGuardDll);
    SetLastError(LastError);
    return std::string("Failed to set Functions from WireGuardNT DLL, ").append(getErrorString(GetLastError()));;
  }

  return "";
}

std::string versionDrive() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"getWgVersion", L"Wireguard-tools.js", NULL);
  DWORD Version = WireGuardGetRunningDriverVersion();
  if (Version == 0) {
    auto statusErr = GetLastError();
    WireGuardCloseAdapter(Adapter);
    if (statusErr == ERROR_FILE_NOT_FOUND) return "Driver not loaded";
    return std::string("Cannot get version drive, ").append(getErrorString(GetLastError()));
  }
  WireGuardCloseAdapter(Adapter);
  return std::string("WireGuardNT v").append(std::to_string((Version >> 16) & 0xff)).append(".").append(std::to_string((Version >> 0) & 0xff));
}

void listDevices::Execute() {
  std::vector<std::string> arrayPrefix;
  arrayPrefix.push_back("ProtectedPrefix\\Administrators\\WireGuard\\");
  arrayPrefix.push_back("WireGuard\\");

  WIN32_FIND_DATA find_data;
  HANDLE find_handle;
  for (auto &preit : arrayPrefix) {
    int ret = 0;
    find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) continue;

    char *iface;
    do {
      if (strncmp(preit.c_str(), find_data.cFileName, strlen(preit.c_str()))) continue;
      iface = find_data.cFileName + strlen(preit.c_str());
      listInfo setInfo;
      setInfo.tunType = "userspace";
      setInfo.pathSock = std::string("\\\\.\\pipe\\").append(preit).append(iface);
      deviceNames[std::string(iface)] = setInfo;
    } while (FindNextFile(find_handle, &find_data));
    FindClose(find_handle);
    if (ret < 0) return SetError(std::string("Erro code: ").append(std::to_string(ret)));
  }

  HDEVINFO dev_info = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, L"SWD\\WireGuard", NULL, DIGCF_PRESENT, NULL, NULL, NULL);
  if (dev_info == INVALID_HANDLE_VALUE) return SetError("Cannot get devices");

  for (DWORD i = 0;; ++i) {
    DWORD buf_len;
    WCHAR adapter_name[MAX_ADAPTER_NAME];
    SP_DEVINFO_DATA dev_info_data;
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
    DEVPROPTYPE prop_type;
    ULONG status, problem_code;
    char *interface_name;

    if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
      if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
      continue;
    }

    if (!SetupDiGetDevicePropertyW(dev_info, &dev_info_data, &devpkey_name, &prop_type, (PBYTE)adapter_name, sizeof(adapter_name), NULL, 0) || prop_type != DEVPROP_TYPE_STRING) continue;
    adapter_name[_countof(adapter_name) - 1] = L'0';
    if (!adapter_name[0]) continue;
    buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, NULL, 0, NULL, NULL);
    if (!buf_len) continue;
    interface_name = (char *)malloc(buf_len);
    if (!interface_name) continue;
    buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, interface_name, buf_len, NULL, NULL);
    if (!buf_len) {
      free(interface_name);
      continue;
    }

    if (CM_Get_DevNode_Status(&status, &problem_code, dev_info_data.DevInst, 0) == CR_SUCCESS && (status & (DN_DRIVER_LOADED | DN_STARTED)) == (DN_DRIVER_LOADED | DN_STARTED)) {
      listInfo setInfo;
      setInfo.tunType = "kernel";
      deviceNames[std::string(interface_name)] = setInfo;
    }
    free(interface_name);
  }
  SetupDiDestroyDeviceInfoList(dev_info);
}

void deleteInterface::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) return SetError("This interface not exists in Wireguard-Tools.js addon!");
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN))) return SetError(std::string("Failed to set down interface, ").append(getErrorString(GetLastError())));
  WireGuardCloseAdapter(Adapter);
}

/**
 * Change point from calloc or malloc
 *
 * T: to
 * C: From
 */
template <typename T, typename C> C* changePoint(T *x) {
  // reinterpret_cast<WIREGUARD_ALLOWED_IP*>(((char*)x) + sizeof(WIREGUARD_PEER));
  // std::cout << "Sizeof: " << sizeof(C) << ", " << typeid(T).name() << " -> " << typeid(C).name() << std::endl;
  return reinterpret_cast<C*>(((char*)x) + sizeof(T));
}

void getConfig::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) return SetError("This interface not exists in Wireguard-Tools.js addon!");
  NET_LUID InterfaceLuid;
  WireGuardGetAdapterLUID(Adapter, &InterfaceLuid);
  try {
    for (auto aip : getIpAddr(InterfaceLuid)) Address.push_back(aip);
  } catch (std::string err) {
    return SetError(err);
  }

  DWORD buf_len = 0;
  WIREGUARD_INTERFACE *wg_iface = nullptr;

  while (!(WireGuardGetConfiguration(Adapter, wg_iface, &buf_len))) {
    free(wg_iface);
    if (GetLastError() != ERROR_MORE_DATA) return SetError((std::string("Failed get interface config, code: ")).append(std::to_string(GetLastError())));
    wg_iface = (WIREGUARD_INTERFACE *)malloc(buf_len);
    if (!wg_iface) return SetError(std::string("Failed get interface config, ").append(std::to_string(-errno)));
  }

  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY) privateKey = wgKeys::toString(wg_iface->PrivateKey);
  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PUBLIC_KEY) publicKey = wgKeys::toString(wg_iface->PublicKey);
  portListen = 0;
  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT) portListen = wg_iface->ListenPort;


  WIREGUARD_PEER *wg_peer = changePoint<WIREGUARD_INTERFACE, WIREGUARD_PEER>(wg_iface);
  for (DWORD i = 0; i < wg_iface->PeersCount; i++) {
    auto pubKey = wgKeys::toString(wg_peer->PublicKey);
    Peer peerConfig;
    peerConfig.last_handshake = 0;
    peerConfig.txBytes = wg_peer->TxBytes;
    peerConfig.rxBytes = wg_peer->RxBytes;

    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY) peerConfig.presharedKey = wgKeys::toString(wg_peer->PresharedKey);
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_ENDPOINT) peerConfig.endpoint = parseEndpoint(&wg_peer->Endpoint);
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE) peerConfig.keepInterval = wg_peer->PersistentKeepalive;
    if (wg_peer->LastHandshake > 0) peerConfig.last_handshake = (wg_peer->LastHandshake / 10000000 - 11644473600LL) * 1000;

    WIREGUARD_ALLOWED_IP* wg_aip = changePoint<WIREGUARD_PEER, WIREGUARD_ALLOWED_IP>(wg_peer);
    for (DWORD __aip = 0; __aip < wg_peer->AllowedIPsCount; __aip++) {
			char saddr[INET6_ADDRSTRLEN];
      if (wg_aip->AddressFamily == AF_INET) {
        inet_ntop(AF_INET, &wg_aip->Address.V6, saddr, INET_ADDRSTRLEN);
        peerConfig.allowedIPs.push_back(std::string(saddr).append("/").append(std::to_string(wg_aip->Cidr)));
			} else if (wg_aip->AddressFamily == AF_INET6) {
        inet_ntop(AF_INET6, &wg_aip->Address.V6, saddr, INET6_ADDRSTRLEN);
        peerConfig.allowedIPs.push_back(std::string(saddr).append("/").append(std::to_string(wg_aip->Cidr)));
			}
      ++wg_aip;
    }
    wg_peer = reinterpret_cast<WIREGUARD_PEER*>(wg_aip);
    peersVector[pubKey] = peerConfig;
  }

  free(wg_iface);
}

void setConfig::Execute() {
  DWORD buf_len = sizeof(WIREGUARD_INTERFACE);
  for (auto peer : peersVector) {
		if (DWORD_MAX - buf_len < sizeof(WIREGUARD_PEER)) return SetError("Buffer overflow");
		buf_len += sizeof(WIREGUARD_PEER);
		for (auto aip : peer.second.allowedIPs) {
			if (DWORD_MAX - buf_len < sizeof(WIREGUARD_ALLOWED_IP)) return SetError("Buffer overflow");
			buf_len += sizeof(WIREGUARD_ALLOWED_IP);
		}
	}
  WIREGUARD_INTERFACE *wg_iface = reinterpret_cast<WIREGUARD_INTERFACE*>(calloc(1, buf_len));
  if (!wg_iface) return SetError("Cannot alloc buff");
  wg_iface->PeersCount = 0;

  wgKeys::stringToKey(wg_iface->PrivateKey, privateKey);
  wg_iface->Flags = WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;

  wg_iface->ListenPort = portListen;
  if (portListen >= 0 && 65535 <= portListen) wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT);

  if (replacePeers) wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_REPLACE_PEERS);

	WIREGUARD_ALLOWED_IP *wg_aip;
	WIREGUARD_PEER *wg_peer = changePoint<WIREGUARD_INTERFACE, WIREGUARD_PEER>(wg_iface);
  for (auto __peer : peersVector) {
    auto peerPublicKey = __peer.first; auto peerConfig = __peer.second;
    try {
      wgKeys::stringToKey(wg_peer->PublicKey, peerPublicKey);
    } catch (std::string &err) {
      SetError(err);
      free(wg_iface);
      return;
    }
    wg_peer->Flags = WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PUBLIC_KEY;
    wg_peer->AllowedIPsCount = 0;
    wg_iface->PeersCount++;

    if (peerConfig.removeMe) {
      wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REMOVE);
      wg_peer = changePoint<WIREGUARD_PEER, WIREGUARD_PEER>(wg_peer);
    } else {
      if (peerConfig.presharedKey.size() == B64_WG_KEY_LENGTH) {
        try {
          wgKeys::stringToKey(wg_peer->PresharedKey, peerConfig.presharedKey);
          wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY);
        } catch (std::string &err) {
          SetError(err);
          free(wg_iface);
          return;
        }
      }

      wg_peer->PersistentKeepalive = peerConfig.keepInterval;
      if (peerConfig.keepInterval >= 0) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);

      if (peerConfig.endpoint.size() > 0) {
        try {
          insertEndpoint(&wg_peer->Endpoint, peerConfig.endpoint.c_str());
          wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_ENDPOINT);
        } catch (std::string &err) {
          SetError(std::string("Cannot parse endpoint, ").append(err));
          free(wg_iface);
          return;
        }
      }

	    wg_aip = changePoint<WIREGUARD_PEER, WIREGUARD_ALLOWED_IP>(wg_peer);
      for (auto aip : peerConfig.allowedIPs) {
        unsigned long cidr = 0;
        if (aip.find("/") != std::string::npos) {
          cidr = std::stoi(aip.substr(aip.find("/")+1));
          aip = aip.substr(0, aip.find("/"));
        }
        aip = aip.substr(0, aip.find("/"));
        wg_aip->AddressFamily = strchr(aip.c_str(), ':') ? AF_INET6 : AF_INET;
        auto status = wg_aip->AddressFamily == AF_INET6 ? inet_pton(wg_aip->AddressFamily, aip.c_str(), &wg_aip->Address.V6) : inet_pton(wg_aip->AddressFamily, aip.c_str(), &wg_aip->Address.V4);
        if (status == 1) {
          if (cidr == 0) cidr = wg_aip->AddressFamily == AF_INET6 ? 128 : 32;
        } else continue;
        wg_aip->Cidr = cidr;
        wg_peer->AllowedIPsCount++;
	      wg_aip = changePoint<WIREGUARD_ALLOWED_IP, WIREGUARD_ALLOWED_IP>(wg_aip);
        if (!(wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REPLACE_ALLOWED_IPS)) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
      }
	    wg_peer = reinterpret_cast<WIREGUARD_PEER*>(((char*)wg_aip));
    }
  }

  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) Adapter = WireGuardCreateAdapter(toLpcwstr(wgName), L"Wireguard-tools.js", NULL);
  if (!Adapter) SetError(std::string("Failed to create adapter, ").append(getErrorString(GetLastError())));
  else if (!WireGuardSetConfiguration(Adapter, reinterpret_cast<WIREGUARD_INTERFACE*>(wg_iface), buf_len)) {
    auto status = GetLastError();
    SetError(std::string("Failed to set interface config, ").append(getErrorString(status)));
    WireGuardCloseAdapter(Adapter);
  } else if (!WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP)) {
    auto status = GetLastError();
    SetError(std::string("Failed to set interface up, ").append(getErrorString(status)));
    WireGuardCloseAdapter(Adapter);
  } else {
    if (Address.size() > 0) {
      std::string IPv4, IPv6;
      for (auto aip : Address) {
        aip = aip.substr(0, aip.find("/"));
        auto family = strchr(aip.c_str(), ':') ? AF_INET6 : AF_INET;
        SOCKADDR_INET address;
        int status = family == AF_INET ? inet_pton(family, aip.c_str(), &address.Ipv4.sin_addr) : inet_pton(family, aip.c_str(), &address.Ipv6.sin6_addr);
        if (status != 1) continue;
        char saddr[INET6_ADDRSTRLEN];
        family == AF_INET ? inet_ntop(AF_INET, &address.Ipv4.sin_addr, saddr, INET_ADDRSTRLEN) : inet_ntop(AF_INET6, &address.Ipv6.sin6_addr, saddr, INET6_ADDRSTRLEN);
        if (family == AF_INET) IPv4 = std::string(saddr);
        // else IPv6 = std::string(saddr);
      }

      if (IPv4.size() > 0 || IPv6.size() > 0) {
        NET_LUID InterfaceLuid;
        WireGuardGetAdapterLUID(Adapter, &InterfaceLuid);
        auto setStatus = insertIpAddr(InterfaceLuid, IPv4, IPv6);
        if (setStatus.size() > 0) SetError(setStatus);
      }
    }
  }
  free(wg_iface);
}