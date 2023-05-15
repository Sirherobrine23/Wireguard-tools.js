#include <napi.h>
#include <string>
#if __linux__
#include "wginterface.cpp"
#else
Napi::Value registerInterface(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Disabled function").ThrowAsJavaScriptException();
  return env.Undefined();
};
Napi::Value setupInterface(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Disabled function").ThrowAsJavaScriptException();
  return env.Undefined();
}
Napi::Value listDevices(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Disabled function").ThrowAsJavaScriptException();
  return env.Undefined();
}
Napi::Value parseWgDeviceV2(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Disabled function").ThrowAsJavaScriptException();
  return env.Undefined();
}
#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("registerInterface", Napi::Function::New(env, registerInterface));
  exports.Set("setupInterface", Napi::Function::New(env, setupInterface));
  exports.Set("listDevices", Napi::Function::New(env, listDevices));
  exports.Set("parseWgDeviceV2", Napi::Function::New(env, parseWgDeviceV2));
  return exports;
}
NODE_API_MODULE(addon, Init);