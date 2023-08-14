#include <napi.h>
#include "wginterface.hh"

Napi::Value listDevicesSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  return Napi::Array::New(env);
}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!(info[0].IsString())) {
    Napi::Error::New(env, "Set wireguard interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(info[1].IsObject())) {
    Napi::Error::New(env, "Set interface config").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  return env.Undefined();
}

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (!(info[0].IsString())) {
    Napi::Error::New(env, "Set wireguard interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  return env.Undefined();
}