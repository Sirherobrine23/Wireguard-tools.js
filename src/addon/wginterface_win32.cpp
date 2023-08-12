#include <napi.h>
#include <map>
#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sysinfoapi.h>
#include <winternl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "wireguard.h"
#include "wginterface.hh"
extern "C" {
  #include "key_maneger.h"
}

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

HMODULE WireGuard;
HMODULE InitializeWireGuardNT(LPCWSTR location = L"wireguard.dll") {
  HMODULE WireGuardDll = LoadLibraryExW(location, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
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

#define CallSetupWireguard 1
// Set wireguard load in Nodejs
void setupWireguard(const Napi::Env& env) {
  WireGuard = InitializeWireGuardNT((LPCWSTR)env.Global().ToObject().Get("wireguardDllPath").ToString().Utf16Value().c_str());
  if (!WireGuard) Napi::Error::New(env, "Failed to initialize WireGuardNT").ThrowAsJavaScriptException();
}

std::string GuidToString(const GUID& interfeceGuid) {
  std::string nGuidString = std::to_string(interfeceGuid.Data1);
  nGuidString = nGuidString.append("-").append(std::to_string(interfeceGuid.Data2)).append("-").append(std::to_string(interfeceGuid.Data3)).append("-");
  nGuidString = nGuidString.append(std::to_string(interfeceGuid.Data4[3]));
  nGuidString = nGuidString.append(std::to_string(interfeceGuid.Data4[4]));
  nGuidString = nGuidString.append(std::to_string(interfeceGuid.Data4[5]));
  nGuidString = nGuidString.append(std::to_string(interfeceGuid.Data4[6]));
  nGuidString = nGuidString.append(std::to_string(interfeceGuid.Data4[7]));
  return nGuidString;
}

std::map<std::string, WIREGUARD_ADAPTER_HANDLE> Adapters;

Napi::Value listDevicesSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  const Napi::Array napiSessions = Napi::Array::New(env);
  for (std::map<std::string, WIREGUARD_ADAPTER_HANDLE>::iterator it = Adapters.begin(); it != Adapters.end(); ++it) napiSessions.Set(napiSessions.Length(), Napi::String::New(env, it->first));
  return napiSessions;
}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!(info[0].IsString())) {
    Napi::Error::New(env, "Require interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (info[0].ToString().Utf8Value().length() > (MAX_ADAPTER_NAME - 1)) {
    Napi::Error::New(env, "interface name is long").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(info[1].IsObject())) {
    Napi::Error::New(env, "Require config interface").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  const Napi::String interfaceName = info[0].ToString();
  const Napi::Object interfaceConfig = info[1].ToObject();
  if (!((interfaceConfig["peers"].IsObject()))) {
    Napi::Error::New(env, "Require peers object!").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Init interface

  // Set Peers
  const Napi::Object Peers = interfaceConfig["peers"].ToObject();
  const Napi::Array Keys = Peers.GetPropertyNames();
  for (uint8_t peerIndex = 0; peerIndex < Keys.Length(); peerIndex++) {
    const Napi::Object peerConfig = Peers.Get(Keys[peerIndex]).As<Napi::Object>();
    const Napi::String peerPubKey = Keys[peerIndex].As<Napi::String>();
  }

  return env.Undefined();
}

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}