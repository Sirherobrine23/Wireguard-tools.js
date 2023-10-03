#include <napi.h>
#include <iostream>
#include "wginterface.hh"

Napi::Object Init(Napi::Env initEnv, Napi::Object exports) {
  /// Call Addon
  #ifdef ONSTARTADDON
  auto status = startAddon(initEnv);
  if (status.length() >= 1) {
    Napi::Error::New(initEnv, status).ThrowAsJavaScriptException();
    return exports;
  }
  #endif

  // Wireguard constants set
  const Napi::Object constants = Napi::Object::New(initEnv);
  constants.Set("WG_B64_LENGTH", B64_WG_KEY_LENGTH);
  constants.Set("WG_LENGTH", WG_KEY_LENGTH);
  constants.Set("MAX_NAME_LENGTH", maxName());
  constants.Set("driveVersion", versionDrive());

  // Constants
  exports.Set("constants", constants);

  // Function's
  #ifdef SETCONFIG
  exports.Set("setConfig", Napi::Function::New(initEnv, [&](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    const auto wgName = info[0];
    const auto wgConfig = info[1];
    Napi::Value ret = env.Undefined();
    if (!(wgName.IsString())) {
      Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
      return env.Undefined();
    } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
      Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
      return env.Undefined();
    } else if (!(wgConfig.IsObject())) {
      Napi::Error::New(env, "Require wireguard config object").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    try {
      auto worker = new setConfig(env, wgName.ToString().Utf8Value(), wgConfig.ToObject());
      worker->Queue();
      return worker->setPromise.Promise();
    } catch (const Napi::Error &err) {
      err.ThrowAsJavaScriptException();
    }
    return ret;
  }));
  #endif

  #ifdef DELIFACE
  exports.Set("deleteInterface", Napi::Function::New(initEnv, [&](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    const auto wgName = info[0];
    if (!(wgName.IsString())) {
      Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
      return env.Undefined();
    } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
      Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    auto worker = new deleteInterface(env, wgName.ToString().Utf8Value());
    worker->Queue();
    return worker->deletePromise.Promise();
  }));
  #endif

  #ifdef GETCONFIG
  exports.Set("getConfig", Napi::Function::New(initEnv, [&](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    const auto wgName = info[0];
    if (!(wgName.IsString())) {
      Napi::Error::New(env, "Require wireguard interface name").ThrowAsJavaScriptException();
      return env.Undefined();
    } else if (wgName.ToString().Utf8Value().length() >= maxName()) {
      Napi::Error::New(env, "interface name is so long").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    try {
      auto worker = new getConfig(env, wgName.ToString().Utf8Value());
      worker->Queue();
      return worker->getPromise.Promise();
    } catch (const Napi::Error &err) {
      err.ThrowAsJavaScriptException();
    }
    return env.Undefined();
  }));
  #endif

  #ifdef LISTDEV
  exports.Set("listDevices", Napi::Function::New(initEnv, [&](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    auto worker = new listDevices(env);
    worker->Queue();
    return worker->listDevicesPromise.Promise();
  }));
  #endif
  return exports;
}
NODE_API_MODULE(addon, Init);