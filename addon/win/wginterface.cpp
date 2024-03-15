#include "wginterface.hh"
#include "genKey/wgkeys.hh"
#include <win/wireguard.h>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <map>
#include <iostream>
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
#include <ws2def.h>
#include <netioapi.h>
#include <chrono>
#include <thread>
#include <comdef.h>
#include <Wbemidl.h>
#include <stdexcept>

const DEVPROPKEY devpkey_name = { { 0x65726957, 0x7547, 0x7261, { 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x4b, 0x65, 0x79 } }, DEVPROPID_FIRST_USABLE + 1 };
#define IFNAMSIZ MAX_ADAPTER_NAME - 1

// Create Wireguard adapter
static WIREGUARD_CREATE_ADAPTER_FUNC *WireGuardCreateAdapter;
// Open Wireguard adapter by name if exists
static WIREGUARD_OPEN_ADAPTER_FUNC *WireGuardOpenAdapter;
// Close Wireguard adapter
static WIREGUARD_CLOSE_ADAPTER_FUNC *WireGuardCloseAdapter;
// Get Wireguard adapter LUID
static WIREGUARD_GET_ADAPTER_LUID_FUNC *WireGuardGetAdapterLUID;
// Get running Wireguard driver version
static WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *WireGuardGetRunningDriverVersion;
// Delete Wireguard driver if non exists adapters
static WIREGUARD_DELETE_DRIVER_FUNC *WireGuardDeleteDriver;
// Set logger for Wireguard adapter
static WIREGUARD_SET_LOGGER_FUNC *WireGuardSetLogger;
// Set adapter logging for Wireguard adapter
static WIREGUARD_SET_ADAPTER_LOGGING_FUNC *WireGuardSetAdapterLogging;
// Get adapter state for Wireguard adapter
static WIREGUARD_GET_ADAPTER_STATE_FUNC *WireGuardGetAdapterState;
// Set adapter state for Wireguard adapter
static WIREGUARD_SET_ADAPTER_STATE_FUNC *WireGuardSetAdapterState;
// Get Wireguard adapter configuration
static WIREGUARD_GET_CONFIGURATION_FUNC *WireGuardGetConfiguration;
// Set Wireguard adapter configuration
static WIREGUARD_SET_CONFIGURATION_FUNC *WireGuardSetConfiguration;

LPCWSTR WireguardAddonDescription = WireguardAddonDescription;

// Function to check if the current user has administrator privileges
bool IsRunAsAdmin() {
  BOOL fRet = FALSE;
  HANDLE hToken = NULL;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
      fRet = Elevation.TokenIsElevated;
    }
  }
  if (hToken) CloseHandle(hToken);
  return !!fRet;
}

std::string convertWcharString(const wchar_t *wideStr) {
  // Create a wstring from the wide character string
  std::wstring wideString(wideStr);

  // Use std::wstring_convert for conversion
  std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
  std::string narrowString = converter.to_bytes(wideString);

  // Now narrowString is a std::string containing the converted string
  return narrowString;
}

LPCWSTR toLpcwstr(std::string s) {
  wchar_t* wString = new wchar_t[s.length()+1];
  MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, wString, s.length()+1);
  return wString;
}

std::string parseEndpoint(SOCKADDR_INET *input) {
  if (!(input->si_family == AF_INET || input->si_family == AF_INET6)) return "";
  char saddr[INET6_ADDRSTRLEN];
  input->si_family == AF_INET ? inet_ntop(AF_INET, &input->Ipv4.sin_addr, saddr, INET_ADDRSTRLEN) : inet_ntop(AF_INET6, &input->Ipv6.sin6_addr, saddr, INET6_ADDRSTRLEN);

  if (input->si_family == AF_INET6) return std::string("[").append(saddr).append("]:").append(std::to_string(htons(input->Ipv6.sin6_port)));
  return std::string(saddr).append(":").append(std::to_string(htons(input->Ipv4.sin_port)));
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

std::string driveLoad(std::map<std::string, std::string> load)  {
  if (!IsRunAsAdmin()) return "Run nodejs with administrator privilegies";
  auto DLLPATH = load["WIN32DLLPATH"];
  if (!(DLLPATH.length())) return "Require Wireguard DLL file path!";
  LPCWSTR dllPath = toLpcwstr(DLLPATH);

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

std::string getWireguardVersion() {
  // Create interface to get version
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"getWgVersion", WireguardAddonDescription, NULL);
  WireGuardCloseAdapter(Adapter);
  DWORD Version = WireGuardGetRunningDriverVersion();
  if (Version == 0) {
    auto statusErr = GetLastError();
    WireGuardCloseAdapter(Adapter);
    if (statusErr == ERROR_FILE_NOT_FOUND) return "Driver not loaded";
    return std::string("Cannot get version drive, ").append(getErrorString(GetLastError()));
  }
  return std::string("WireGuardNT v").append(std::to_string((Version >> 16) & 0xff)).append(".").append(std::to_string((Version >> 0) & 0xff)).append(".").append(std::to_string((Version >> 8) & 0xff));
}

void WireguardDevices::getInterfaces() {
  HDEVINFO dev_info = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, L"SWD\\WireGuard", NULL, DIGCF_PRESENT, NULL, NULL, NULL);
  if (dev_info == INVALID_HANDLE_VALUE) throw std::string("Cannot get devices");
  for (DWORD devIndex = 0;; ++devIndex) {
    SP_DEVINFO_DATA dev_info_data;
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiEnumDeviceInfo(dev_info, devIndex, &dev_info_data)) {
      if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
      continue;
    }

    DWORD buf_len; ULONG status, problem_code;
    WCHAR adapter_name[MAX_ADAPTER_NAME];
    char *interface_name;
    DEVPROPTYPE prop_type;

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

    if (CM_Get_DevNode_Status(&status, &problem_code, dev_info_data.DevInst, 0) == CR_SUCCESS && (status & (DN_DRIVER_LOADED | DN_STARTED)) == (DN_DRIVER_LOADED | DN_STARTED)) this->push_back(std::string(interface_name));
    free(interface_name);
  }
  SetupDiDestroyDeviceInfoList(dev_info);
}

/*
  Delete wireguard interface

  Current bug from Addon: Set interface down and not delete wireguard interface
*/
void WireguardDevices::deleteInterface(std::string wgName) {
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(wgName));
  if (!Adapter) throw std::string("This interface not exists in Wireguard-Tools.js addon!");
  if (!(WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_DOWN))) throw std::string("Failed to set down interface, ").append(getErrorString(GetLastError()));
  WireGuardCloseAdapter(Adapter);
}

/**
 * Change point from calloc or malloc, T: from, C: to
 */
template <typename T, typename C> C* changePoint(T *x) {
  return reinterpret_cast<C*>(((char*)x) + sizeof(T));
}

void WireguardConfig::getWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Require interface name!");
  else if (!(WireguardDevices().exist(this->name))) throw std::string("This interface not exists in Wireguard-Tools.js addon!");

  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(this->name));
  if (!Adapter) throw std::string("This interface not exists in Wireguard-Tools.js addon!");
  NET_LUID InterfaceLuid;
  WireGuardGetAdapterLUID(Adapter, &InterfaceLuid);
  this->interfaceAddress.GetInInterface(this->name);

  DWORD buf_len = 0;
  WIREGUARD_INTERFACE *wg_iface = nullptr;

  while (!(WireGuardGetConfiguration(Adapter, wg_iface, &buf_len))) {
    free(wg_iface);
    if (GetLastError() != ERROR_MORE_DATA) throw std::string("Failed get interface config, code: ").append(std::to_string(GetLastError()));
    wg_iface = (WIREGUARD_INTERFACE *)malloc(buf_len);
    if (!wg_iface) throw std::string("Failed get interface config, ").append(std::to_string(-errno));
  }

  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY) this->privateKey = wgKeys::toString(wg_iface->PrivateKey);
  if (wg_iface->Flags & WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PUBLIC_KEY) this->publicKey = wgKeys::toString(wg_iface->PublicKey);
  if (wg_iface->ListenPort > 0) this->portListen = wg_iface->ListenPort;

  WIREGUARD_PEER *wg_peer = changePoint<WIREGUARD_INTERFACE, WIREGUARD_PEER>(wg_iface);
  for (DWORD i = 0; i < wg_iface->PeersCount; i++) {
    auto pubKey = wgKeys::toString(wg_peer->PublicKey);
    Peer peerConfig;

    peerConfig.txBytes = wg_peer->TxBytes;
    peerConfig.rxBytes = wg_peer->RxBytes;
    peerConfig.lastHandshake = (wg_peer->LastHandshake - 116444736000000000LL) / (100 / 1000);

    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY) peerConfig.presharedKey = wgKeys::toString(wg_peer->PresharedKey);
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_ENDPOINT) peerConfig.endpoint = parseEndpoint(&wg_peer->Endpoint);
    if (wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE) peerConfig.keepInterval = wg_peer->PersistentKeepalive;

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
    this->Peers[pubKey] = peerConfig;
  }

  free(wg_iface);
}

void WireguardConfig::setWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Require interface name!");
  else if (this->name.length() > IFNAMSIZ) throw std::string("Interface name too long");

  DWORD buf_len = sizeof(WIREGUARD_INTERFACE);
  for (auto peer : this->Peers) {
		if (DWORD_MAX - buf_len < sizeof(WIREGUARD_PEER)) throw std::string("Buffer overflow");
		buf_len += sizeof(WIREGUARD_PEER);
		for (auto aip : peer.second.allowedIPs) {
			if (DWORD_MAX - buf_len < sizeof(WIREGUARD_ALLOWED_IP)) throw std::string("Buffer overflow");
			buf_len += sizeof(WIREGUARD_ALLOWED_IP);
		}
	}
  WIREGUARD_INTERFACE *wg_iface = reinterpret_cast<WIREGUARD_INTERFACE*>(calloc(1, buf_len));
  if (!wg_iface) throw std::string("Cannot alloc buff");
  wg_iface->PeersCount = 0;

  wgKeys::stringToKey(wg_iface->PrivateKey, this->privateKey);
  wg_iface->Flags = WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_PRIVATE_KEY;

  wg_iface->ListenPort = this->portListen;
  if (this->portListen >= 0) wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
  if (this->replacePeers) wg_iface->Flags = (WIREGUARD_INTERFACE_FLAG)(wg_iface->Flags|WIREGUARD_INTERFACE_FLAG::WIREGUARD_INTERFACE_REPLACE_PEERS);

	WIREGUARD_ALLOWED_IP *wg_aip;
	WIREGUARD_PEER *wg_peer = changePoint<WIREGUARD_INTERFACE, WIREGUARD_PEER>(wg_iface);
  for (auto __peer : this->Peers) {
    auto peerPublicKey = __peer.first; auto peerConfig = __peer.second;
    wgKeys::stringToKey(wg_peer->PublicKey, peerPublicKey);
    wg_peer->Flags = WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PUBLIC_KEY;
    wg_peer->AllowedIPsCount = 0;
    wg_iface->PeersCount++;

    if (peerConfig.removeMe) {
      wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REMOVE);
      wg_peer = changePoint<WIREGUARD_PEER, WIREGUARD_PEER>(wg_peer);
    } else {
      if (peerConfig.presharedKey.size() == B64_WG_KEY_LENGTH) {
        wgKeys::stringToKey(wg_peer->PresharedKey, peerConfig.presharedKey);
        wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PRESHARED_KEY);
      }

      wg_peer->PersistentKeepalive = peerConfig.keepInterval;
      if (peerConfig.keepInterval >= 0) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);

      if (peerConfig.endpoint.size() > 0) {
        int ret, retries = ([]() -> int {
          unsigned long ret;
          char *retries = getenv("WG_ENDPOINT_RESOLUTION_RETRIES"), *end;

          if (!retries) return 15;
          if (!strcmp(retries, "infinity")) return -1;

          ret = strtoul(retries, &end, 10);
          if (*end || ret > INT_MAX) {
            fprintf(stderr, "Unable to parse WG_ENDPOINT_RESOLUTION_RETRIES: `%s'\n", retries);
            exit(1);
          }
          return (int)ret;
        })();

        char *begin, *end;
        auto mmutable = strdup(peerConfig.endpoint.c_str());
        if (!mmutable) throw std::string("strdup");
        if (!peerConfig.endpoint.size()) {
          free(mmutable);
          throw std::string("Unable to parse empty endpoint");
        }
        if (mmutable[0] == '[') {
          begin = &mmutable[1];
          end = strchr(mmutable, ']');
          if (!end) {
            free(mmutable);
            throw std::string("Unable to find matching brace of endpoint: ").append(peerConfig.endpoint);
          }
          *end++ = '\0';
          if (*end++ != ':' || !*end) {
            free(mmutable);
            throw std::string("Unable to find port of endpoint: ").append(peerConfig.endpoint);
          }
        } else {
          begin = mmutable;
          end = strrchr(mmutable, ':');
          if (!end || !*(end + 1)) {
            free(mmutable);
            throw std::string("Unable to find port of endpoint: ").append(peerConfig.endpoint);
          }
          *end++ = '\0';
        }

        ADDRINFOA *resolved;
        for (unsigned int timeout = 1000000;; timeout = ((20000000) < (timeout * 6 / 5) ? (20000000) : (timeout * 6 / 5))) {
          // ret = getaddrinfo(begin, end, &hints, &resolved);
          ret = getaddrinfo(begin, end, NULL, &resolved);
          if (!ret) break;
          if (ret == EAI_NONAME || ret == EAI_FAIL ||
            #ifdef EAI_NODATA
              ret == EAI_NODATA ||
            #endif
              (retries >= 0 && !retries--)) {
            free(mmutable);
            throw std::string("Error code: ").append(std::to_string(ret));
          }
          std::this_thread::sleep_for(std::chrono::microseconds(timeout));
        }

        if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(SOCKADDR_IN))) memcpy(&wg_peer->Endpoint.Ipv4, resolved->ai_addr, resolved->ai_addrlen);
        else if (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(SOCKADDR_IN6)) memcpy(&wg_peer->Endpoint.Ipv6, resolved->ai_addr, resolved->ai_addrlen);
        else {
          freeaddrinfo(resolved);
          throw std::string("Neither IPv4 nor IPv6 address found: ").append(peerConfig.endpoint);
        }
        freeaddrinfo(resolved);
        free(mmutable);

        wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_HAS_ENDPOINT);
      }

	    wg_aip = changePoint<WIREGUARD_PEER, WIREGUARD_ALLOWED_IP>(wg_peer);
      for (auto Ip : peerConfig.allowedIPs.getIpParsed()) {
        wg_aip->AddressFamily = Ip.Proto == 4 ? AF_INET : AF_INET6;
        wg_aip->Cidr = Ip.Mask;

        if (Ip.Proto == 6 && inet_pton(AF_INET6, Ip.Address.c_str(), &wg_aip->Address.V6) == 1) wg_aip->AddressFamily = AF_INET6;
        else if (Ip.Proto == 4 && inet_pton(AF_INET, Ip.Address.c_str(), &wg_aip->Address.V4) == 1) wg_aip->AddressFamily = AF_INET;
        else continue;

        wg_peer->AllowedIPsCount++;
	      wg_aip = changePoint<WIREGUARD_ALLOWED_IP, WIREGUARD_ALLOWED_IP>(wg_aip);
        if (!(wg_peer->Flags & WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REPLACE_ALLOWED_IPS)) wg_peer->Flags = (WIREGUARD_PEER_FLAG)(wg_peer->Flags|WIREGUARD_PEER_FLAG::WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
      }
	    wg_peer = reinterpret_cast<WIREGUARD_PEER*>(((char*)wg_aip));
    }
  }

  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(this->name));
  if (!Adapter) Adapter = WireGuardCreateAdapter(toLpcwstr(this->name), WireguardAddonDescription, NULL);
  if (!Adapter) throw std::string("Failed to create adapter, ").append(getErrorString(GetLastError()));

  auto status = WireGuardSetConfiguration(Adapter, reinterpret_cast<WIREGUARD_INTERFACE*>(wg_iface), buf_len) && WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE::WIREGUARD_ADAPTER_STATE_UP);
  free(wg_iface);

  if (!status) {
    auto status = GetLastError();
    WireGuardCloseAdapter(Adapter);
    throw std::string("Failed to set interface config, ").append(getErrorString(status));
  }

  this->interfaceAddress.SetInInterface(this->name);
}

void IpManeger::GetInInterface(std::string interfaceName) {
  // Define the InterfaceLuid of the network interface you want to query
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(interfaceName));
  if (!Adapter) throw std::string("Cannot open wireguard adapter");
  NET_LUID InterfaceLuid;
  WireGuardGetAdapterLUID(Adapter, &InterfaceLuid);

  ULONG bufferSize = 0; // Initial buffer size
  // Call GetAdaptersAddresses to get the required buffer size
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
    // Allocate memory for the buffer
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(bufferSize));
    // Call GetAdaptersAddresses again with the allocated buffer
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) == NO_ERROR) {
      // Iterate through the list of adapters
      for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        // Check if the adapter matches the specified InterfaceLuid
        if (memcmp(&adapter->Luid, &InterfaceLuid, sizeof(NET_LUID)) == 0) {
          // Iterate through the list of IP addresses associated with the adapter
          for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress; address != nullptr; address = address->Next) {
            // Access the IP address in the address structure
            sockaddr* sa = address->Address.lpSockaddr;
            char ip[INET6_ADDRSTRLEN];
            if (sa->sa_family == AF_INET) {
              inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(sa)->sin_addr, ip, sizeof(ip));
            } else if (sa->sa_family == AF_INET6) {
              inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr, ip, sizeof(ip));
            } else continue;
            // Print or use the IP address as needed
            this->addIPMask(std::string(ip).append("/").append(std::to_string(address->Address.iSockaddrLength)));
          }
        }
      }
    }

    // Free the allocated buffer
    free(addresses);
  }
}

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry
void IpManeger::SetInInterface(std::string interfaceName) {
  if (this->size() == 0) return;
  WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardOpenAdapter(toLpcwstr(interfaceName));
  if (!Adapter) throw std::string("Cannot open wireguard adapter");

  NET_LUID InterfaceLuid;
  WireGuardGetAdapterLUID(Adapter, &InterfaceLuid);
  ULONG bufferSize = 0; // Initial buffer size
  // Call GetAdaptersAddresses to get the required buffer size
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
    // Allocate memory for the buffer
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(bufferSize));
    // Call GetAdaptersAddresses again with the allocated buffer
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) == NO_ERROR) {
      // Iterate through the list of adapters
      for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        // Check if the adapter matches the specified InterfaceLuid
        if (memcmp(&adapter->Luid, &InterfaceLuid, sizeof(NET_LUID)) == 0) {
          // Iterate through the list of IP addresses associated with the adapter
          for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress; address != nullptr; address = address->Next) {
            // Access the IP address in the address structure
            sockaddr* sa = address->Address.lpSockaddr;
            char ip[INET6_ADDRSTRLEN];
            if (sa->sa_family == AF_INET) {
              inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(sa)->sin_addr, ip, sizeof(ip));
            } else if (sa->sa_family == AF_INET6) {
              inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr, ip, sizeof(ip));
            } else continue;

            // Delete the IP address
            MIB_UNICASTIPADDRESS_ROW row;
            memset(&row, 0, sizeof(row));
            WireGuardGetAdapterLUID(Adapter, &row.InterfaceLuid);
            if (sa->sa_family == AF_INET) {
              row.Address.si_family = AF_INET;
              inet_pton(AF_INET, ip, &row.Address.Ipv4.sin_addr);
            } else if (sa->sa_family == AF_INET6) {
              row.Address.si_family = AF_INET6;
              inet_pton(AF_INET6, ip, &row.Address.Ipv6.sin6_addr);
            } else continue;

            if (DeleteUnicastIpAddressEntry(&row) != NO_ERROR) throw std::string("Cannot delete IP address from interface");
          }
        }
      }
    }

    // Free the allocated buffer
    free(addresses);
  }

  for (auto ip : this->getIpParsed()) {
    MIB_UNICASTIPADDRESS_ROW row;
    memset(&row, 0, sizeof(row));
    memcpy(&row.InterfaceLuid, &InterfaceLuid, sizeof(NET_LUID));

    row.DadState = NldsPreferred;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;

    row.OnLinkPrefixLength = ip.Mask;
    if (ip.Proto == 4) {
      row.Address.si_family = AF_INET;
      inet_pton(AF_INET, ip.Address.c_str(), &row.Address.Ipv4.sin_addr);
    } else if (ip.Proto == 6) {
      row.Address.si_family = AF_INET6;
      inet_pton(AF_INET6, ip.Address.c_str(), &row.Address.Ipv6.sin6_addr);
    } else continue;

    if (CreateUnicastIpAddressEntry(&row) != NO_ERROR) throw std::string("Cannot add IP address to interface");
  }
}