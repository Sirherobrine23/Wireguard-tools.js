#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include "wireguard-nt/include/wireguard.h"
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
#include <ndisguid.h>
#include <win/shared.cpp>
#include "wginterface.hh"

const DEVPROPKEY devpkey_name = { { 0x65726957, 0x7547, 0x7261, { 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x4b, 0x65, 0x79 } }, 3 };
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

LPCWSTR toLpcwstr(std::string s) {
  wchar_t* wString = new wchar_t[s.length()+1];
  MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, wString, s.length()+1);
  return wString;
}

std::string startAddon(const Napi::Env env) {
  if (!IsRunAsAdmin()) return "Run nodejs with administrator privilegies";
  auto DLLPATH = env.Global().ToObject().Get("WIREGUARD_DLL_PATH");
  if (!(DLLPATH.IsString())) return "Require WIREGUARD_DLL_PATH in Global process";
  LPCWSTR dllPath = toLpcwstr(DLLPATH.ToString());

  HMODULE WireGuardDll = LoadLibraryExW(dllPath, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!WireGuardDll) return ((std::string)"Failed to initialize WireGuardNT, ").append(getErrorString(GetLastError()));;
  #define X(Name) ((*(FARPROC *)&Name = GetProcAddress(WireGuardDll, #Name)) == NULL)
  if (X(WireGuardCreateAdapter) || X(WireGuardOpenAdapter) || X(WireGuardCloseAdapter) || X(WireGuardGetAdapterLUID) || X(WireGuardGetRunningDriverVersion) || X(WireGuardDeleteDriver) || X(WireGuardSetLogger) || X(WireGuardSetAdapterLogging) || X(WireGuardGetAdapterState) || X(WireGuardSetAdapterState) || X(WireGuardGetConfiguration) || X(WireGuardSetConfiguration))
  #undef X
  {
    DWORD LastError = GetLastError();
    FreeLibrary(WireGuardDll);
    SetLastError(LastError);
    return ((std::string)"Failed to set Functions from WireGuardNT DLL, ").append(getErrorString(GetLastError()));;
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
    return ((std::string)"Cannot get version drive, ").append(getErrorString(GetLastError()));
  }
  WireGuardCloseAdapter(Adapter);
  return ((std::string)"WireGuardNT v").append(std::to_string((Version >> 16) & 0xff)).append(".").append(std::to_string((Version >> 0) & 0xff));
}

typedef uint8_t wg_key[32];
typedef char wg_key_b64_string[((sizeof(wg_key) + 2) / 3) * 4 + 1];
bool key_is_zero(const uint8_t key[32])
{
	volatile uint8_t acc = 0;

	for (unsigned int i = 0; i < 32; ++i) {
		acc |= key[i];
		// asm volatile("" : "=r"(acc) : "0"(acc));
	}
	return !!(1 & ((acc - 1) >> 8));
}

static int decodeBase64(const char src[4]) {
  int val = 0;
  unsigned int i;

  for (i = 0; i < 4; ++i) val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)) << (18 - 6 * i);
  return val;
}

static void encode_base64(char dest[4], const uint8_t src[3]) {
  const uint8_t input[] = {
    static_cast<uint8_t>((src[0] >> 2) & 63),
    static_cast<uint8_t>(((src[0] << 4) | (src[1] >> 4)) & 63),
    static_cast<uint8_t>(((src[1] << 2) | (src[2] >> 6)) & 63),
    static_cast<uint8_t>(src[2] & 63)
  };
  unsigned int i;
  for (i = 0; i < 4; ++i) dest[i] = input[i] + 'A' + (((25 - input[i]) >> 8) & 6) - (((51 - input[i]) >> 8) & 75) - (((61 - input[i]) >> 8) & 15) + (((62 - input[i]) >> 8) & 3);
}

void insertKey(wg_key key, std::string keyBase64) {
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

std::string keyToBase64(const wg_key key) {
  wg_key_b64_string base64;
  unsigned int i;

  for (i = 0; i < 32 / 3; ++i) encode_base64(&base64[i * 4], &key[i * 3]);
  const uint8_t tempKey[3] = { key[i * 3 + 0], key[i * 3 + 1], 0 };
  encode_base64(&base64[i * 4], tempKey);
  base64[sizeof(wg_key_b64_string) - 2] = '=';
  base64[sizeof(wg_key_b64_string) - 1] = '\0';

  return std::string(base64);
}

void listDevices::Execute() {
  std::vector<std::string> arrayPrefix;
  arrayPrefix.push_back("ProtectedPrefix\\Administrators\\WireGuard\\");
  arrayPrefix.push_back("WireGuard\\");

  WIN32_FIND_DATA find_data;
  HANDLE find_handle;
  int ret = 0;
  for (auto &preit : arrayPrefix) {
    ret = 0;
    find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) continue;

    char *iface;
    do {
      if (strncmp(preit.c_str(), find_data.cFileName, strlen(preit.c_str()))) continue;
      iface = find_data.cFileName + strlen(preit.c_str());
      deviceNames[std::string(iface)] = "kernel";
    } while (FindNextFile(find_handle, &find_data));
    FindClose(find_handle);
    if (ret < 0) {
      std::string err = "Erro code: ";
      err = err.append(std::to_string(ret));
      return SetError(err);
    }
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

		if (CM_Get_DevNode_Status(&status, &problem_code, dev_info_data.DevInst, 0) == CR_SUCCESS && (status & (DN_DRIVER_LOADED | DN_STARTED)) == (DN_DRIVER_LOADED | DN_STARTED)) deviceNames[std::string(interface_name)] = "kernel";
	}
	SetupDiDestroyDeviceInfoList(dev_info);
}

void deleteInterface::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) return SetError("This interface not exists in Wireguard-Tools.js addon!");
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN))) return SetError(((std::string)"Failed to set down interface, ").append(getErrorString(GetLastError())));
  WireGuardCloseAdapter(Adapter);
}

void getConfig::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) return SetError("This interface not exists in Wireguard-Tools.js addon!");
  DWORD buf_len = 0;
  WIREGUARD_INTERFACE *wg_iface;

  while (!(WireGuardGetConfiguration(Adapter, wg_iface, &buf_len))) {
    if (GetLastError() != ERROR_MORE_DATA) return SetError((std::string("Failed get interface config, code: ")).append(std::to_string(GetLastError())));
    wg_iface = (WIREGUARD_INTERFACE *)malloc(buf_len);
    if (!wg_iface) return SetError(((std::string)"Failed get interface config, ").append(std::to_string(-errno)));
  }

  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT) portListen = wg_iface->ListenPort;
  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY) privateKey = keyToBase64(wg_iface->PrivateKey);
  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PUBLIC_KEY) publicKey = keyToBase64(wg_iface->PublicKey);

  WIREGUARD_PEER* wg_peer = (WIREGUARD_PEER*)wg_iface + sizeof(WIREGUARD_INTERFACE);
  for (ULONG i = 0; i < wg_iface->PeersCount; ++i) {
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PUBLIC_KEY) break;
    auto publicKey = keyToBase64(wg_peer->PublicKey);
    Peer peerObj;

    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY) {
      if (!(key_is_zero(wg_peer->PresharedKey))) peerObj.presharedKey = keyToBase64(wg_peer->PresharedKey);
    }

    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE) peerObj.keepInterval = wg_peer->PersistentKeepalive;
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_ENDPOINT) {
      if (wg_peer->Endpoint.si_family == AF_INET) {}
      else if (wg_peer->Endpoint.si_family == AF_INET6) {}
    }
    peerObj.rxBytes = wg_peer->RxBytes;
		peerObj.txBytes = wg_peer->TxBytes;
    if (wg_peer->LastHandshake) peerObj.last_handshake = (wg_peer->LastHandshake / 10000000 - 11644473600LL) * 1000;
    WIREGUARD_ALLOWED_IP *wg_aip = (WIREGUARD_ALLOWED_IP *)wg_peer + sizeof(WIREGUARD_PEER);
		for (ULONG j = 0; j < wg_peer->AllowedIPsCount; ++j) {
			if (wg_aip->AddressFamily == AF_INET) {
				char saddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &wg_aip->Address.V6, saddr, INET_ADDRSTRLEN);
        peerObj.allowedIPs.push_back(std::string(saddr).append("/").append(std::to_string(wg_aip->Cidr)));
			} else if (wg_aip->AddressFamily == AF_INET6) {
				char saddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &wg_aip->Address.V6, saddr, INET6_ADDRSTRLEN);
        std::string(saddr).append("/").append(std::to_string(wg_aip->Cidr));
			}
			++wg_aip;
		}
		wg_peer = (WIREGUARD_PEER*)wg_aip;
    peersVector[publicKey] = peerObj;
  }

  free(wg_iface);
}

void setConfig::Execute() {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) {
    Adapter = WireGuardCreateAdapter(toLpcwstr(wgName), L"Wireguard-tools.js", NULL);
    if (!Adapter) return SetError(((std::string)"Failed to create adapter, ").append(getErrorString(GetLastError())));
  }
  DWORD buf_len;
  for (auto peer : peersVector) {
    if (DWORD_MAX - buf_len < sizeof(WIREGUARD_PEER)) {
      WireGuardCloseAdapter(Adapter);
      return SetError("Overflow buff");
    }
    buf_len += sizeof(WIREGUARD_PEER);
    for (auto aip : peer.second.allowedIPs) {
      if (DWORD_MAX - buf_len < sizeof(WIREGUARD_ALLOWED_IP)) {
        WireGuardCloseAdapter(Adapter);
        return SetError("Overflow buff");
      }
      buf_len += sizeof(WIREGUARD_ALLOWED_IP);
    }
  }
  WIREGUARD_INTERFACE *wg_iface = (WIREGUARD_INTERFACE*)calloc(1, buf_len);
  if (!wg_iface) {
    WireGuardCloseAdapter(Adapter);
    return SetError("Cannot alloc buff to config");
  }

  if (privateKey.size() == WG_KEY_LENGTH) {
    try {
      insertKey(wg_iface->PrivateKey, privateKey);
      wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY);
    } catch (std::string &err) {
      WireGuardCloseAdapter(Adapter);
      return SetError(((std::string)"Invalid privateKey, ").append(err));
    }
  }

  if (portListen >= 0) {
    wg_iface->ListenPort = portListen;
    wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
  }

  if (replacePeers) wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_REPLACE_PEERS);

  size_t peer_count = 0, aip_count;
	WIREGUARD_PEER *wg_peer = (WIREGUARD_PEER*)wg_iface + sizeof(WIREGUARD_INTERFACE);
  WIREGUARD_ALLOWED_IP *wg_aip;
  for (auto& peer : peersVector) {
    try {
      insertKey(wg_peer->PublicKey, peer.first);
      wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PUBLIC_KEY);
    } catch (std::string &err) {
      WireGuardCloseAdapter(Adapter);
      return SetError(((std::string)"Invalid publicKey, ").append(err));
    }

    if (peer.second.removeMe) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REMOVE);
    else {
      if (peer.second.presharedKey.size() == WG_KEY_LENGTH) {
        try {
          insertKey(wg_peer->PresharedKey, peer.second.presharedKey);
          wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY);
        } catch (std::string &err) {
          WireGuardCloseAdapter(Adapter);
          return SetError(((std::string)"Invalid presharedKey, ").append(err));
        }
      }
      if (peer.second.keepInterval > 0) {
        wg_peer->PersistentKeepalive = peer.second.keepInterval;
        wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);
      }
      if (peer.second.allowedIPs.size() > 0) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
    }

    aip_count = 0;
		wg_aip = (WIREGUARD_ALLOWED_IP*)wg_peer + sizeof(WIREGUARD_PEER);
    if (!peer.second.removeMe) {
      for (auto aip : peer.second.allowedIPs) {
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
        } else if (status == -1) {
          WireGuardCloseAdapter(Adapter);
          return SetError(((std::string)"Invalid IP address, ").append(std::to_string(WSAGetLastError())));
        } else continue;
        wg_aip->Cidr = cidr;
        ++aip_count;
        ++wg_aip;
      }
    }
    wg_peer->AllowedIPsCount = aip_count;

    ++peer_count;
    wg_peer = (WIREGUARD_PEER*)wg_aip;
  }
  wg_iface->PeersCount = peer_count;

  if (!WireGuardSetConfiguration(Adapter, wg_iface, buf_len)) {
    free(wg_iface);
    auto status = GetLastError();
    WireGuardCloseAdapter(Adapter);
    return SetError(((std::string)"Failed to set interface config, ").append(getErrorString(status)));
  }
  free(wg_iface);
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP))) {
    return SetError(((std::string)"Failed to set Up interface, ").append(getErrorString(GetLastError())));
  }
}