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
  } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
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

Napi::Value deleteInterfaceAsync(const Napi::CallbackInfo &info) {
  const Napi::Env env = info.Env();
  const auto wgName = info[0];
  const auto callback = info[1];
  if (!(wgName.IsString())) {
    Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
    Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(callback.IsFunction())) {
    Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  try {
    const auto delInterWorker = new deleteInterface(callback.As<Napi::Function>(), wgName.ToString().Utf8Value());
    delInterWorker->Queue();
  } catch (const Napi::Error &err) {
    err.ThrowAsJavaScriptException();
  }
  return env.Undefined();
}

Napi::Value getConfigAsync(const Napi::CallbackInfo &info) {
  const Napi::Env env = info.Env();
  const auto wgName = info[0];
  const auto callback = info[1];
  if (!(wgName.IsString())) {
    Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
    Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(callback.IsFunction())) {
    Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  try {
    const auto ssconfig = new getConfig(callback.As<Napi::Function>(), wgName.ToString().Utf8Value());
    ssconfig->Queue();
  } catch (const Napi::Error &err) {
    err.ThrowAsJavaScriptException();
  }
  return env.Undefined();
}

Napi::Value listDevicesAsync(const Napi::CallbackInfo &info) {
  const Napi::Env env = info.Env();
  const auto callback = info[0];
  if (!(callback.IsFunction())) {
    Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  try {
    const auto devicesFind = new listDevices(callback.As<Napi::Function>());
    devicesFind->Queue();
  } catch (const Napi::Error &err) {
    err.ThrowAsJavaScriptException();
  }
  return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  /// Call Addon
  #ifdef ONSTARTADDON
  auto status = startAddon(env);
  if (status.length() >= 1) {
    Napi::Error::New(env, status).ThrowAsJavaScriptException();
    return exports;
  }
  #endif

  // Wireguard constants set
  const Napi::Object constants = Napi::Object::New(env);
  constants.Set("WG_B64_LENGTH", WG_KEY_LENGTH);
  constants.Set("MAX_NAME_LENGTH", maxName());
  constants.Set("driveVersion", versionDrive());

  // Constants
  exports.Set("constants", constants);

  // Function's
  #ifdef SETCONFIG
  exports.Set("setConfigAsync", Napi::Function::New(env, setConfigAsync));
  #endif

  #ifdef DELIFACE
  exports.Set("deleteInterfaceAsync", Napi::Function::New(env, deleteInterfaceAsync));
  #endif

  #ifdef GETCONFIG
  exports.Set("getConfigAsync", Napi::Function::New(env, getConfigAsync));
  #endif

  #ifdef LISTDEV
  exports.Set("listDevicesAsync", Napi::Function::New(env, listDevicesAsync));
  #endif
  return exports;
}
NODE_API_MODULE(addon, Init);