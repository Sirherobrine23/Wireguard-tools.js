#define NAPI_DISABLE_CPP_EXCEPTIONS
// N-API
#include <napi.h>
#include <unistd.h>
#include <string>
#include "add_new_device.cc"
#include "parse_device.cc"

Napi::Value getDevice(const Napi::CallbackInfo& info) {
  char *device_name = strdup(info[0].As<Napi::String>().Utf8Value().c_str());
  wg_device *device;
  if (wg_get_device(&device, device_name) < 0) return Napi::String::New(info.Env(), "Error getting device");
  return parseWgDevice(info, device);
}

Napi::Value getDevices(const Napi::CallbackInfo& info) {
  char *device_names, *device_name;
  device_names = wg_list_device_names();
  if (!device_names) return Napi::String::New(info.Env(),"Unable to get device names");
  Napi::Object wgRootObject = Napi::Object::New(info.Env());
  size_t len;
  wg_for_each_device_name(device_names, device_name, len) {
    wg_device *device;
    if (wg_get_device(&device, device_name) < 0) continue;
    Napi::Value DeviceObj = parseWgDevice(info, device);
    if (DeviceObj.IsString()) {
      printf("Get devices error: '%s'\n", DeviceObj.As<Napi::String>().Utf8Value().c_str());
      continue;
    }
    wgRootObject.Set(Napi::String::New(info.Env(), device_name), DeviceObj);
  }
  free(device_names);
  return wgRootObject;
}

Napi::Value delDevie(const Napi::CallbackInfo& info) {return Napi::Number::New(info.Env(), wg_del_device(info[0].As<Napi::String>().Utf8Value().c_str()));};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("addNewDevice", Napi::Function::New(env, addNewDevice));
  exports.Set("delDevice", Napi::Function::New(env, delDevie));
  exports.Set("getDevices", Napi::Function::New(env, getDevices));
  exports.Set("getDevice", Napi::Function::New(env, getDevice));
  return exports;
}
NODE_API_MODULE(addon, Init)
