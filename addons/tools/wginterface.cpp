#include <napi.h>
#include "wginterface.hh"

/** Wireguard function to exec async set config */
Napi::Value setConfigAsync(const Napi::CallbackInfo &info) {
  const Napi::Env env = info.Env();
  const auto wgName = info[0];
  const auto wgConfig = info[1];
  const auto callback = info[2];
  if (!(wgName.IsString())) {
    Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (wgName.ToString().Utf8Value().length() > maxName()) {
    Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(wgConfig.IsObject())) {
    Napi::Error::New(env, "Require wireguard config object").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(callback.IsFunction())) {
    Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  try {
    const auto ssconfig = new setConfig(env, callback.As<Napi::Function>(), wgName.ToString().Utf8Value(), wgConfig.ToObject());
    ssconfig->Queue();
  } catch (const Napi::Error &err) {
    err.ThrowAsJavaScriptException();
  }
  return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  const Napi::Object constants = Napi::Object::New(env);
  constants.Set("MAX_NAME_LENGTH", maxName());

  // Constants
  exports.Set("constants", constants);

  // async function
  exports.Set("setConfigAsync", Napi::Function::New(env, setConfigAsync));

  // Sync function lock loop
  exports.Set("listDevicesSync", Napi::Function::New(env, listDevicesSync));
  exports.Set("setupInterfaceSync", Napi::Function::New(env, setupInterfaceSync));
  exports.Set("parseWgDeviceSync", Napi::Function::New(env, parseWgDeviceSync));
  return exports;
}
NODE_API_MODULE(addon, Init);