#include <napi.h>
#include "wginterface.hh"

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  const Napi::Object constants = Napi::Object::New(env);
  constants.Set("MAX_NAME_LENGTH", maxName());

  // Constants
  exports.Set("constants", constants);

  exports.Set("listDevicesSync", Napi::Function::New(env, listDevicesSync));
  exports.Set("setupInterfaceSync", Napi::Function::New(env, setupInterfaceSync));
  exports.Set("parseWgDeviceSync", Napi::Function::New(env, parseWgDeviceSync));
  return exports;
}
NODE_API_MODULE(addon, Init);