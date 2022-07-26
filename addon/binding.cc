#include <napi.h>
#include <uv.h>
#include "wgEmbed/wireguard.h"
#include "wgEmbed/wireguard.c"

// Export the binding to nodejs
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  // exports.Set("getDevices", Napi::Function::New(getDevices));
  return exports;
}
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)