#include <napi.h>
#include <string>
#include "wginterface.hh"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  #ifdef CallSetupWireguard
    setupWireguard(env);
  #endif

  exports.Set("listDevicesSync", Napi::Function::New(env, listDevicesSync));
  exports.Set("setupInterfaceSync", Napi::Function::New(env, setupInterfaceSync));
  exports.Set("parseWgDeviceSync", Napi::Function::New(env, parseWgDeviceSync));
  return exports;
}
NODE_API_MODULE(addon, Init);