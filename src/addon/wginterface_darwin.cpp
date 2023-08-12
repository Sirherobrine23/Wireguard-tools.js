#include <napi.h>
#include "wginterface.hh"
#include "sys/socket.h"

void setupWireguard(const Napi::Env& env) {}

Napi::Value listDevicesSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}

Napi::Value listDevicesAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}

Napi::Value setupInterfaceAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}

Napi::Value parseWgDeviceAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return env.Undefined();
}