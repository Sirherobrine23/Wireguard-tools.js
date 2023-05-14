#include <napi.h>
#include <string>
#include "key_gen.cpp"
#if __linux__
#include "parse_device.cc"
#include "add_device.cpp"
Napi::Value delDevice(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), wg_del_device(info[0].As<Napi::String>().Utf8Value().c_str()));
};
Napi::Value addDevice(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), wg_add_device(info[0].As<Napi::String>().Utf8Value().c_str()));
};
#endif

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  #if __linux__
  exports.Set("removeInterface", Napi::Function::New(env, delDevice));
  exports.Set("addInterface", Napi::Function::New(env, addDevice));
  exports.Set("setupInterface", Napi::Function::New(env, setupInterface));
  exports.Set("listDevices", Napi::Function::New(env, listDevices));
  exports.Set("parseWgDeviceV2", Napi::Function::New(env, parseWgDeviceV2));
  #endif
  exports.Set("keyGen", initKeyGen(env));
  return exports;
}
NODE_API_MODULE(addon, Init);