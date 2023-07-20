#include <napi.h>
#include <string>
#include "wginterface.hh"

#ifndef LISTDEVICESSYNC
std::string DefaultMessageList = "Current System/arch not support list devices";
Napi::Value listDevicesSync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  Napi::Error::New(env,DefaultMessageList).ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value listDevicesAsync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  command[command.Length() - 1].As<Napi::Function>().Call(command.This(), {Napi::Error::New(env, DefaultMessageList).Value()});
  return env.Undefined();
}
#endif

#ifndef SETUPDEVICESSYNC
std::string DefaultMessageSetup = "Current System/arch not support config/setup interface";
Napi::Value setupInterfaceSync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  Napi::Error::New(env,DefaultMessageSetup).ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value setupInterfaceAsync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  command[command.Length() - 1].As<Napi::Function>().Call(command.This(), {Napi::Error::New(env, DefaultMessageSetup).Value()});
  return env.Undefined();
}
#endif

#ifndef PARSEDEVICESSYNC
std::string DefaultMessageParse = "Current System/arch not support get configs from Interface";
Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  Napi::Error::New(env,DefaultMessageParse).ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value parseWgDeviceAsync(const Napi::CallbackInfo& command) {
  Napi::Env env = command.Env();
  command[command.Length() - 1].As<Napi::Function>().Call(command.This(), {Napi::Error::New(env, DefaultMessageParse).Value()});
  return env.Undefined();
}
#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("listDevicesSync", Napi::Function::New(env, listDevicesSync));
  exports.Set("listDevicesAsync", Napi::Function::New(env, listDevicesAsync));

  exports.Set("setupInterfaceSync", Napi::Function::New(env, setupInterfaceSync));
  exports.Set("setupInterfaceAsync", Napi::Function::New(env, setupInterfaceAsync));

  exports.Set("parseWgDeviceSync", Napi::Function::New(env, parseWgDeviceSync));
  exports.Set("parseWgDeviceAsync", Napi::Function::New(env, parseWgDeviceAsync));
  return exports;
}
NODE_API_MODULE(addon, Init);